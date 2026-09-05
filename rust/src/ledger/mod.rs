//! Ledger hardware-wallet signer over USB-HID.
//!
//! Unlike the other backends in this crate (which talk to remote HTTP APIs),
//! the Ledger backend drives a physical device on the local machine through
//! [`solana-remote-wallet`](https://docs.rs/solana-remote-wallet) — Solana's
//! canonical Ledger APDU client. The private key never leaves the device, and
//! every signature must be confirmed on the device screen.
//!
//! ## Why one shared, permanent device thread
//!
//! Two independent reasons, and the second is the strict one.
//!
//! `solana-remote-wallet` is single-threaded: its `RemoteWalletManager` and
//! `LedgerWallet` handles are reference-counted with [`std::rc::Rc`] and wrap a
//! `hidapi` device that is not [`Sync`], while the [`SolanaSigner`] trait is
//! `async` and `Send + Sync`. Confining device I/O to one OS thread bridges
//! that, and is correct on its own terms — a Ledger services one APDU exchange
//! at a time.
//!
//! But the thread must also be a **process-wide singleton that never exits**,
//! because of how IOKit schedules HID devices on macOS. See [`DEVICE_THREAD`]:
//! a per-signer thread makes any connect/drop/reconnect cycle abort the process.
//!
//! So [`LedgerSigner`] owns no thread and no device handle at all — just a
//! cached pubkey and a derivation path. Each trait method does a blocking
//! request/reply against the shared thread from inside
//! [`tokio::task::spawn_blocking`].
//!
//! Works under any of `sdk-v2`/`sdk-v3`/`sdk-v4`. The backend needs
//! `solana-remote-wallet` 4.x — the first line carrying the Nano Gen5 product
//! IDs — whose solana-* crates do not match the ones `sdk-v2`/`sdk-v3` select.
//! That costs nothing here: pubkeys and signatures cross to the selected SDK as
//! raw bytes (see [`signature_bytes`]), so the two majors coexist in the
//! dependency graph and no type is ever required to unify.

mod dashboard;

use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use solana_derivation_path::DerivationPath;
use solana_remote_wallet::ledger::LedgerWallet;
use solana_remote_wallet::remote_wallet::{
    initialize_wallet_manager, RemoteWallet, RemoteWalletError, RemoteWalletType,
};

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, VersionedTransaction};
use crate::traits::{SignTransactionResult, SolanaSigner, TransactionSigner};
use crate::transaction_util::TransactionUtil;

/// Default Solana derivation path: `m/44'/501'/0'`.
///
/// This matches **Ledger Live**'s Solana accounts (account index, no "change"
/// component), so the address pay derives equals the one a user sees and funds
/// in Ledger Live. (The 4-component `m/44'/501'/0'/0'` is the older Solana-CLI
/// style and derives a *different* address.)
pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/501'/0'";

/// Timeout for device commands that **cannot** involve the user.
///
/// Enumeration, an unconfirmed pubkey read and the liveness probe are pure
/// host-to-device exchanges: the device either answers in milliseconds or
/// something is wrong. Seconds is generous.
pub const FAST_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for commands that wait on a human.
///
/// Signing blocks while the user reads the confirm screen, so this cannot be
/// short. It is bounded by the device's own auto-lock: once the Ledger locks,
/// the prompt is gone and no answer is ever coming, so waiting past that window
/// only prolongs the stall. Five minutes sits inside Ledger's ten-minute
/// default auto-lock while still being long enough for a user who stepped away
/// mid-approval. Override with [`LedgerConfig::signing_timeout`].
pub const DEFAULT_SIGNING_TIMEOUT: Duration = Duration::from_secs(300);

/// How to open a [`LedgerSigner`].
///
/// Prefer this over [`LedgerSigner::connect`] when you need to control the
/// signing timeout or suppress the dashboard auto-launch. `Default` reproduces
/// `connect(None, false, None)` exactly.
#[derive(Debug, Clone)]
pub struct LedgerConfig {
    /// BIP-44 path; `None` uses [`DEFAULT_DERIVATION_PATH`].
    pub derivation_path: Option<String>,
    /// Display the derived address on the device for the user to verify. This
    /// requires a button press, so it waits on [`Self::signing_timeout`].
    pub confirm_pubkey_on_device: bool,
    /// Select one device by OS HID path when several Ledgers are attached.
    pub host_device_path: Option<String>,
    /// How long to wait on a command that needs a human. Defaults to
    /// [`DEFAULT_SIGNING_TIMEOUT`].
    pub signing_timeout: Duration,
    /// Launch the Solana app from the BOLOS dashboard when a connect fails
    /// because the app is not running. Defaults to `true`.
    ///
    /// **This writes APDUs to the device without asking the host user**, and on
    /// most firmware the device then shows its own confirmation prompt. That is
    /// the right default for an interactive CLI, where the alternative is
    /// telling the user to go and navigate the device by hand. Set it to `false`
    /// for unattended or server-side use, where a process should not be poking a
    /// security device on its own initiative; connect then fails with the
    /// underlying "open the Solana app" error instead. A decline on the device
    /// is always surfaced as [`SignerError::UserRejected`] either way.
    pub auto_open_app: bool,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            derivation_path: None,
            confirm_pubkey_on_device: false,
            host_device_path: None,
            signing_timeout: DEFAULT_SIGNING_TIMEOUT,
            auto_open_app: true,
        }
    }
}

/// Requests sent to the device-actor thread. Each carries a one-shot reply
/// channel the actor uses to return the result.
enum DeviceCommand {
    /// Establish (or reuse) a device session and read the pubkey at `path_str`.
    Connect {
        path_str: String,
        confirm_pubkey_on_device: bool,
        host_device_path: Option<String>,
        /// Launch the Solana app from the dashboard if the connect fails.
        auto_open_app: bool,
        reply: Sender<Result<[u8; 32], SignerError>>,
    },
    /// Sign serialized transaction-message bytes (Solana app "sign" APDU).
    SignTransactionMessage {
        path_str: String,
        message: Vec<u8>,
        reply: Sender<Result<[u8; 64], SignerError>>,
    },
    /// Sign an off-chain message (Solana app "sign off-chain message" APDU).
    SignOffchainMessage {
        path_str: String,
        message: Vec<u8>,
        reply: Sender<Result<[u8; 64], SignerError>>,
    },
    /// Liveness probe: can we read the pubkey without on-device confirmation?
    IsAvailable {
        path_str: String,
        reply: Sender<bool>,
    },
    /// Is any Ledger attached, regardless of whether it is usable?
    ///
    /// Exists so callers never have to touch `hidapi` themselves; see
    /// [`device_channel`] for why that matters.
    IsAttached { reply: Sender<bool> },
}

/// The one, process-wide device thread. Started on first use, never joined.
///
/// ## Why it must be a singleton
///
/// On macOS, `hidapi::HidApi::new()` enumerates through IOKit, which schedules
/// each HID device onto **the calling thread's `CFRunLoop`**
/// (`IOHIDDeviceScheduleWithRunLoop` <- `CFRunLoopAddSource`). When that thread
/// exits, its run loop goes with it, but IOKit's process-global HID manager
/// still holds the scheduled sources. The next `HidApi::new()` on a *different*
/// thread then re-applies device matching over that stale state, and the process
/// dies with SIGTRAP inside CoreFoundation's `__CFCheckCFInfoPACSignature`.
///
/// So a per-signer device thread cannot work: any create/drop/reconnect cycle
/// crashes the process. Single operations always looked fine, which is exactly
/// what made this read as a flaky test rather than a lifecycle bug. Confirmed
/// from the crash report -- the faulting frames are the chain above.
///
/// One thread that never exits keeps every HID source scheduled on a run loop
/// that stays alive, which is the only arrangement IOKit tolerates. It is also
/// the right shape anyway: a Ledger services one APDU exchange at a time, so
/// serialising through a single thread costs nothing.
static DEVICE_THREAD: std::sync::OnceLock<Sender<DeviceCommand>> = std::sync::OnceLock::new();

/// Channel to the device thread, starting it if this is the first call.
///
/// Everything that touches `hidapi` must go through here; calling
/// `HidApi::new()` from any other thread is what crashes. See [`DEVICE_THREAD`].
fn device_channel() -> &'static Sender<DeviceCommand> {
    DEVICE_THREAD.get_or_init(|| {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        // The handle is deliberately dropped: this thread outlives every signer,
        // so there is nothing to join and no handle worth keeping.
        std::thread::Builder::new()
            .name("ledger-device".to_string())
            .spawn(move || device_thread(cmd_rx))
            .expect("failed to spawn the Ledger device thread");
        cmd_tx
    })
}

/// A [`SolanaSigner`] backed by a Ledger hardware wallet.
///
/// Cheap to create and drop: it holds no thread and no device handle, only the
/// cached pubkey and the derivation path to use. All device work happens on the
/// shared thread described at [`DEVICE_THREAD`].
pub struct LedgerSigner {
    pubkey: Pubkey,
    path_str: String,
    /// Timeout for the device commands that wait on a button press.
    signing_timeout: Duration,
}

impl std::fmt::Debug for LedgerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerSigner")
            .field("pubkey", &self.pubkey)
            .finish_non_exhaustive()
    }
}

impl LedgerSigner {
    /// Connect to a Ledger device and cache the public key at `derivation_path`
    /// (defaults to [`DEFAULT_DERIVATION_PATH`]).
    ///
    /// Set `confirm_pubkey_on_device` to display the derived address on the
    /// device screen for the user to verify — use this when *registering* an
    /// account, not on every signing connection.
    ///
    /// `host_device_path` selects a specific device by its OS HID path when more
    /// than one Ledger is connected. Pass `None` to use the sole connected
    /// device; if several are attached and `None` is given, this returns
    /// [`SignerError::NotAvailable`] listing each device's path so the caller can
    /// retry with a specific one.
    ///
    /// Requires the Ledger to be plugged in, unlocked, and running the Solana
    /// app. On Linux, the appropriate `udev` rules must be installed.
    ///
    /// **Blocking:** this blocks the calling thread until the device responds —
    /// with `confirm_pubkey_on_device` set, until the user presses a button. Do
    /// not call it directly from an async task; use the async
    /// [`Signer::from_ledger`](crate::Signer::from_ledger) factory (which runs it
    /// on the blocking pool) or wrap it in [`tokio::task::spawn_blocking`].
    pub fn connect(
        derivation_path: Option<&str>,
        confirm_pubkey_on_device: bool,
        host_device_path: Option<&str>,
    ) -> Result<Self, SignerError> {
        Self::connect_with(LedgerConfig {
            derivation_path: derivation_path.map(str::to_string),
            confirm_pubkey_on_device,
            host_device_path: host_device_path.map(str::to_string),
            ..LedgerConfig::default()
        })
    }

    /// Connect using an explicit [`LedgerConfig`].
    ///
    /// Use this to set the signing timeout or to turn off the dashboard
    /// auto-launch; see [`LedgerConfig`] for what each option costs.
    ///
    /// **Blocking**, exactly as [`LedgerSigner::connect`] is. Every command this
    /// signer later issues is bounded: [`FAST_COMMAND_TIMEOUT`] for exchanges
    /// that cannot involve the user, and [`LedgerConfig::signing_timeout`] for
    /// the ones that wait on a button press.
    pub fn connect_with(config: LedgerConfig) -> Result<Self, SignerError> {
        let LedgerConfig {
            derivation_path,
            confirm_pubkey_on_device,
            host_device_path,
            signing_timeout,
            auto_open_app,
        } = config;

        let path_str = derivation_path.unwrap_or_else(|| DEFAULT_DERIVATION_PATH.to_string());
        // Validate before troubling the device, so a typo is a clear config
        // error rather than an obscure APDU failure.
        DerivationPath::from_absolute_path_str(&path_str)
            .map_err(|e| SignerError::ConfigError(format!("invalid derivation path: {e}")))?;

        // A connect can reach the user in two ways: an explicit on-device
        // address confirmation, and the dashboard auto-launch, which most
        // firmware asks the user to approve. Either one means this has to wait
        // on a human rather than on the wire.
        let timeout = if confirm_pubkey_on_device || auto_open_app {
            signing_timeout
        } else {
            FAST_COMMAND_TIMEOUT
        };

        let pubkey_bytes = request_on(device_channel(), timeout, |reply| DeviceCommand::Connect {
            path_str: path_str.clone(),
            confirm_pubkey_on_device,
            host_device_path,
            auto_open_app,
            reply,
        })?;

        Ok(Self {
            pubkey: Pubkey::from(pubkey_bytes),
            path_str,
            signing_timeout,
        })
    }

    /// The timeout this signer applies to commands that wait on a button press.
    pub fn signing_timeout(&self) -> Duration {
        self.signing_timeout
    }

    /// Is a Ledger attached, whether or not it is usable right now?
    ///
    /// Answers without requiring the device to be unlocked or the Solana app to
    /// be open, so a caller can tell "no hardware" apart from "hardware present
    /// but not ready" — which are very different things to report to a user.
    /// Goes through the device thread; see [`DEVICE_THREAD`].
    pub fn is_attached() -> bool {
        if check_actor_responsive().is_err() {
            // The device thread is stuck on an earlier command, so it cannot
            // answer this either. Reporting "no device" would be a lie, but so
            // would blocking: this probe exists to be quick.
            return false;
        }
        let cmd_tx = device_channel();
        let (reply_tx, reply_rx) = mpsc::channel();
        if cmd_tx
            .send(DeviceCommand::IsAttached { reply: reply_tx })
            .is_err()
        {
            return false;
        }
        match reply_rx.recv_timeout(FAST_COMMAND_TIMEOUT) {
            Ok(attached) => attached,
            Err(RecvTimeoutError::Timeout) => {
                mark_abandoned();
                false
            }
            Err(RecvTimeoutError::Disconnected) => false,
        }
    }
}

#[async_trait::async_trait]
impl SolanaSigner for LedgerSigner {
    fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    /// Sign `message` as a Solana **off-chain message**.
    ///
    /// A hardware wallet cannot raw-ed25519-sign arbitrary bytes the way the
    /// software backends do. It signs a *structured* off-chain message: the
    /// payload is wrapped in an envelope and the device signs the envelope. The
    /// returned signature therefore covers the **envelope**, not the raw
    /// `message` bytes — a plain `signature.verify(pubkey, message)` over the
    /// payload will fail. Rebuild the same bytes with
    /// [`ledger_offchain_envelope`] to verify. This deviates from the raw-bytes
    /// contract of the software backends by necessity; see the `sign_message`
    /// note on [`SolanaSigner`].
    ///
    /// Note the envelope is **not** what `solana_offchain_message` produces —
    /// see [`ledger_offchain_envelope`] for why, and for the layout.
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let serialized = ledger_offchain_envelope(&self.pubkey, message)?;
        // Kept for the post-signing verification below; `serialized` itself moves
        // into the device closure.
        let verify_against = serialized.clone();
        let path_str = self.path_str.clone();
        let timeout = self.signing_timeout;
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(device_channel(), timeout, |reply| {
                DeviceCommand::SignOffchainMessage {
                    path_str,
                    message: serialized,
                    reply,
                }
            })
        })
        .await
        .map_err(|e| SignerError::Other(format!("Ledger signing task failed: {e}")))??;
        let signature = Signature::from(sig_bytes);
        // Same signature-binding invariant the remote backends hold to: never
        // hand back a signature that does not verify against this signer's key
        // over the bytes we computed. Here that also pins the envelope: the
        // device signed the envelope, so verification is against it and not the
        // raw payload.
        crate::signature_util::verify_or_reject(&signature, &self.pubkey, &verify_against)?;
        Ok(signature)
    }

    /// Liveness probe. Never waits on the user, so it is bounded by
    /// [`FAST_COMMAND_TIMEOUT`] rather than the signing timeout, and reports
    /// `false` rather than blocking when the device thread is wedged.
    async fn is_available(&self) -> bool {
        let path_str = self.path_str.clone();
        tokio::task::spawn_blocking(move || {
            if check_actor_responsive().is_err() {
                return false;
            }
            let (reply_tx, reply_rx) = mpsc::channel();
            if device_channel()
                .send(DeviceCommand::IsAvailable {
                    path_str,
                    reply: reply_tx,
                })
                .is_err()
            {
                return false;
            }
            match reply_rx.recv_timeout(FAST_COMMAND_TIMEOUT) {
                Ok(available) => available,
                Err(RecvTimeoutError::Timeout) => {
                    mark_abandoned();
                    false
                }
                Err(RecvTimeoutError::Disconnected) => false,
            }
        })
        .await
        .unwrap_or(false)
    }
}

#[async_trait::async_trait]
impl TransactionSigner for LedgerSigner {
    /// Sign `tx` on the device, in place.
    ///
    /// The serialized transaction *message* goes to the Solana app's
    /// transaction-parsing APDU, which is the only way a Ledger will sign a
    /// transaction — it cannot raw-ed25519-sign arbitrary bytes. Legacy, v0 and
    /// v1 all work, because what crosses to the device is
    /// `VersionedMessage::serialize()` either way; the device renders what it
    /// can parse and falls back to blind signing otherwise (which the user must
    /// have enabled in the app's settings).
    ///
    /// The signature covers exactly the bytes the caller supplied, so it
    /// verifies identically to a software backend's and needs no special
    /// handling server-side.
    async fn sign_transaction(
        &self,
        tx: &mut VersionedTransaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let message = tx.message.serialize();
        // Kept for the post-signing verification below; `message` itself moves
        // into the device closure.
        let verify_against = message.clone();
        let path_str = self.path_str.clone();
        let timeout = self.signing_timeout;
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(device_channel(), timeout, |reply| {
                DeviceCommand::SignTransactionMessage {
                    path_str,
                    message,
                    reply,
                }
            })
        })
        .await
        .map_err(|e| SignerError::Other(format!("Ledger signing task failed: {e}")))??;

        let signature = Signature::from(sig_bytes);
        // Signature binding, as the remote backends do it: reject rather than
        // attach if the device's signature does not verify against this signer's
        // key over the exact bytes we sent. On a hardware path this is what
        // catches a transport-level corruption, or a device answering for a
        // different derivation path than the one we cached a pubkey for.
        crate::signature_util::verify_or_reject(&signature, &self.pubkey, &verify_against)?;
        TransactionUtil::add_signature_to_transaction(tx, &self.pubkey(), signature)?;
        let signed_transaction = (TransactionUtil::serialize_transaction(tx)?, signature);
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            signed_transaction,
        ))
    }
}

/// Longest payload that fits an off-chain message envelope bound for a Ledger.
///
/// Two independent caps apply and the tighter one wins. The device rejects a
/// total envelope over `MAX_OFFCHAIN_MESSAGE_LENGTH` (Solana's 1232-byte packet
/// size). Before that, `solana-remote-wallet` refuses to send anything over
/// `v0::OffchainMessage::MAX_LEN_LEDGER + v0::OffchainMessage::HEADER_LEN`
/// = 1212 + 3 = 1215, a guard it computes from the *crate's* header size (3) and
/// not the header the device actually parses (85). Its guard is therefore the
/// binding one, and 1215 - 85 is what is left for the payload.
pub const MAX_OFFCHAIN_PAYLOAD_LEN: usize = 1215 - OFFCHAIN_HEADER_LEN_ONE_SIGNER;

/// Envelope header length for a single signer:
/// 16 (signing domain) + 1 (version) + 32 (application domain) + 1 (format)
/// + 1 (signer count) + 32 (one signer) + 2 (message length).
const OFFCHAIN_HEADER_LEN_ONE_SIGNER: usize = 16 + 1 + 32 + 1 + 1 + 32 + 2;

/// Build the off-chain message envelope the **Ledger Solana app** expects.
///
/// This deliberately does not use `solana_offchain_message`, because that crate
/// and the Ledger app implement different layouts and the crate's output is
/// rejected outright. Verified against a real Nano Gen5: the crate's envelope
/// returns APDU `SolanaInvalidMessageHeader`, exactly as raw unwrapped bytes do,
/// which is why simply "wrapping the payload" did not fix off-chain signing.
///
/// What the crate emits (20-byte header):
///   signing domain (16) ‖ version (1) ‖ format (1) ‖ length (2) ‖ message
///
/// What the app parses for v0 (85-byte header for one signer):
///   signing domain (16) ‖ version=0 (1) ‖ **application domain (32)**
///   ‖ format (1) ‖ **signer count (1)** ‖ **signers (32 each)**
///   ‖ length (2, little-endian) ‖ message
///
/// The crate omits the application domain, the signer count and the signer list
/// — 65 bytes for a single signer. The signer list is the part that matters
/// most: the app derives the pubkey at the requested path and rejects the
/// message unless that pubkey appears in the list, so the envelope has to name
/// the signer. (Source: `LedgerHQ/app-solana`, `libsol/parser.c`
/// `parse_offchain_message_header` and `src/handle_sign_offchain_message.c`.)
///
/// The application domain is left all-zero, which the app supports explicitly
/// and displays as "Domain not provided". A future integration that wants the
/// device to show a bound application identity should populate it — the value is
/// covered by the signature, so it cannot be altered in flight.
///
/// The format byte is derived from the payload rather than fixed: 0
/// (RestrictedAscii) when the payload is printable ASCII, 1 (LimitedUtf8)
/// otherwise. Format 2 (ExtendedUtf8) is deliberately unsupported by hardware
/// wallets per the spec, and the app rejects it, so a payload that is not valid
/// UTF-8 is refused here rather than at the device.
pub fn ledger_offchain_envelope(signer: &Pubkey, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
    // The app rejects a zero-length message (`header.length == 0`).
    if payload.is_empty() {
        return Err(SignerError::ConfigError(
            "off-chain message payload is empty; a Ledger will not sign it".to_string(),
        ));
    }
    if payload.len() > MAX_OFFCHAIN_PAYLOAD_LEN {
        return Err(SignerError::ConfigError(format!(
            "off-chain message payload is {} bytes; a Ledger accepts at most {}",
            payload.len(),
            MAX_OFFCHAIN_PAYLOAD_LEN
        )));
    }
    // Mirror the app's own content checks so the failure is local and legible
    // rather than an opaque APDU rejection after a round-trip.
    let format: u8 = if payload.iter().all(|b| (0x20..=0x7e).contains(b)) {
        0 // RestrictedAscii
    } else if std::str::from_utf8(payload).is_ok() {
        1 // LimitedUtf8
    } else {
        return Err(SignerError::ConfigError(
            "off-chain message payload is not valid UTF-8; a Ledger will not sign it".to_string(),
        ));
    };

    let mut out = Vec::with_capacity(OFFCHAIN_HEADER_LEN_ONE_SIGNER + payload.len());
    // Taken from the crate rather than hardcoded, so the domain stays in step
    // with upstream even though the rest of the layout cannot.
    out.extend_from_slice(solana_offchain_message::OffchainMessage::SIGNING_DOMAIN);
    out.push(0); // header version 0
    out.extend_from_slice(&[0u8; 32]); // application domain: not provided
    out.push(format);
    out.push(1); // exactly one signer
    out.extend_from_slice(&signer.to_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    debug_assert_eq!(out.len(), OFFCHAIN_HEADER_LEN_ONE_SIGNER + payload.len());
    Ok(out)
}

/// Number of commands the device thread has finished, ever.
///
/// Paired with [`ABANDONED_AT`] to tell "the actor is busy" apart from "the
/// actor is wedged", which a caller cannot otherwise observe.
static COMPLETED: AtomicU64 = AtomicU64::new(0);

/// The [`COMPLETED`] count at the moment a caller last gave up waiting, or
/// `u64::MAX` when no timeout is outstanding.
static ABANDONED_AT: AtomicU64 = AtomicU64::new(u64::MAX);

/// Record that a caller stopped waiting for a reply.
fn mark_abandoned() {
    ABANDONED_AT.store(COMPLETED.load(Ordering::SeqCst), Ordering::SeqCst);
}

/// Refuse to enqueue behind a command that is still blocking the device thread.
///
/// This is the part that a caller-side timeout alone does not solve, and it is
/// why the timeout is not the whole fix. The actor is a single serialized
/// thread, and the HID read it blocks in has no timeout of its own:
/// `solana-remote-wallet`'s `Ledger::read` calls `hidapi`'s blocking
/// `HidDevice::read`. So when a command wedges, giving the *caller* its thread
/// back leaves the actor stuck forever, and without this check every later
/// command from every other signer in the process would queue behind it and
/// burn its own full timeout in turn -- turning one stalled prompt into a
/// process-wide stall that degrades one timeout at a time.
///
/// Failing fast is the honest answer: the device genuinely cannot serve anyone
/// until the stuck exchange resolves. The moment the actor finishes anything,
/// `COMPLETED` moves past the recorded mark and normal service resumes by
/// itself, so a slow user who eventually presses the button costs nothing.
fn check_actor_responsive() -> Result<(), SignerError> {
    let abandoned = ABANDONED_AT.load(Ordering::SeqCst);
    if abandoned == u64::MAX {
        return Ok(());
    }
    if COMPLETED.load(Ordering::SeqCst) > abandoned {
        // The actor drained the stuck command; stop reporting it as wedged.
        let _ =
            ABANDONED_AT.compare_exchange(abandoned, u64::MAX, Ordering::SeqCst, Ordering::SeqCst);
        return Ok(());
    }
    Err(SignerError::NotAvailable(
        "the Ledger device thread is still blocked on an earlier command that timed out. \
         Dismiss any prompt left on the device screen, or unplug and replug it, then retry."
            .to_string(),
    ))
}

/// Send a command to the device actor and block for its reply, up to `timeout`.
///
/// Called from inside `spawn_blocking`. On timeout the reply receiver is
/// dropped, which the actor detects when it finally answers: see
/// [`respond`], which drops the cached session so the next connect
/// re-establishes rather than reusing a handle left mid-exchange.
fn request_on<T: Send + 'static>(
    cmd_tx: &Sender<DeviceCommand>,
    timeout: Duration,
    build: impl FnOnce(Sender<Result<T, SignerError>>) -> DeviceCommand,
) -> Result<T, SignerError> {
    check_actor_responsive()?;
    let (reply_tx, reply_rx) = mpsc::channel();
    cmd_tx.send(build(reply_tx)).map_err(|_| {
        SignerError::NotAvailable("Ledger device thread is not running".to_string())
    })?;
    match reply_rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            mark_abandoned();
            Err(SignerError::NotAvailable(format!(
                "Ledger did not respond within {}s. If a confirmation is waiting on the device \
                 screen, answer it and retry; otherwise unplug and replug the device.",
                timeout.as_secs()
            )))
        }
        Err(RecvTimeoutError::Disconnected) => Err(SignerError::NotAvailable(
            "Ledger device thread stopped".to_string(),
        )),
    }
}

/// Answer a command, noticing when the caller has already given up.
///
/// `send` fails only if the reply receiver was dropped, which happens exactly
/// when [`request_on`] timed out. That command may have left the device
/// mid-exchange, so the cached session is no longer trustworthy and is dropped.
fn respond<T>(session: &mut Option<Session>, reply: &Sender<T>, result: T) {
    if reply.send(result).is_err() {
        *session = None;
    }
    COMPLETED.fetch_add(1, Ordering::SeqCst);
}

/// The device-actor thread body. Owns the single-threaded `solana-remote-wallet`
/// handles and serves [`DeviceCommand`]s until the command channel closes.
/// Establish a device session: enumerate, select, and read the pubkey.
///
/// Runs only on the device thread. Returns the wallet handle so the caller can
/// cache it for subsequent commands.
fn establish_session(
    path: &DerivationPath,
    confirm_pubkey_on_device: bool,
    host_device_path: Option<&str>,
) -> Result<(Rc<LedgerWallet>, [u8; 32]), SignerError> {
    // A failure to bring up the HID subsystem is an *availability* problem,
    // not a signing failure — map it to NotAvailable directly rather than
    // letting map_rw_err's catch-all bucket it as SigningFailed (which would
    // also make the no-device unit test panic on CI runners lacking libhidapi).
    let manager = initialize_wallet_manager()
        .map_err(|e| SignerError::NotAvailable(format!("Ledger HID subsystem unavailable: {e}")))?;
    let count = manager.update_devices().map_err(map_rw_err)?;
    if count == 0 {
        return Err(SignerError::NotAvailable(
            "no Ledger device found (plug in, unlock, and open the Solana app)".to_string(),
        ));
    }

    // `list_devices` filters to valid Ledger wallets by VID/PID + HID usage,
    // but it also enumerates Trezor (and optionally Keystone) devices. The
    // `wallet_type` variant is what identifies a Ledger — not the model,
    // which is the device *name* ("nano-gen5", "nano-x", "stax", …) and never
    // "ledger". Taking the `Rc<LedgerWallet>` straight out of the variant
    // also removes the second `get_wallet`/`get_ledger` lookup by path.
    let ledgers: Vec<Rc<LedgerWallet>> = manager
        .list_devices()
        .into_iter()
        .filter_map(|d| match d.wallet_type {
            RemoteWalletType::Ledger(wallet) => Some(wallet),
            _ => None,
        })
        .collect();

    // Deterministic device selection: honor an explicit host path; otherwise
    // require exactly one device rather than silently picking the first (the
    // enumeration order is OS-dependent and unstable across re-plugs).
    let ledger = match host_device_path {
        Some(want) => ledgers
            .into_iter()
            .find(|w| hid_path(w).as_deref() == Some(want))
            .ok_or_else(|| {
                SignerError::NotAvailable(format!("no Ledger device at host path `{want}`"))
            })?,
        None => match ledgers.len() {
            0 => {
                return Err(SignerError::NotAvailable(
                    "no Ledger device found".to_string(),
                ))
            }
            1 => ledgers.into_iter().next().expect("len == 1"),
            _ => {
                // `pretty_path` is the canonical Solana device locator
                // (`usb://ledger/<base pubkey>`) — stable across re-plugs,
                // unlike the OS HID path, so it is the useful half of the
                // disambiguation hint even though the path is what selects.
                let list = ledgers
                    .iter()
                    .map(|w| {
                        format!(
                            "  {} ({})",
                            hid_path(w).unwrap_or_else(|| "<unknown path>".to_string()),
                            w.pretty_path
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(SignerError::NotAvailable(format!(
                    "multiple Ledger devices connected; pass host_device_path to select one:\n{list}"
                )));
            }
        },
    };

    let pubkey = ledger
        .get_pubkey(path, confirm_pubkey_on_device)
        .map_err(map_rw_err)?;
    Ok((ledger, pubkey.to_bytes()))
}

/// A live device session, cached on the device thread between commands.
struct Session {
    wallet: Rc<LedgerWallet>,
    /// The host path this session was opened against, so a `Connect` asking for
    /// a *different* device re-establishes instead of silently using this one.
    host_device_path: Option<String>,
}

/// The device thread body. Runs for the life of the process.
///
/// Holds at most one open session and reuses it across commands, so repeated
/// `LedgerSigner::connect` calls do not re-enumerate HID. Any device error drops
/// the session, so the next connect re-establishes rather than reusing a handle
/// to a device that has been unplugged, locked or switched apps.
fn device_thread(cmd_rx: Receiver<DeviceCommand>) {
    let mut session: Option<Session> = None;

    // Every command needs the caller's derivation path parsed; `connect` has
    // already validated it, so a failure here is genuinely unexpected.
    fn parse(path_str: &str) -> Result<DerivationPath, SignerError> {
        DerivationPath::from_absolute_path_str(path_str)
            .map_err(|e| SignerError::ConfigError(format!("invalid derivation path: {e}")))
    }

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            DeviceCommand::Connect {
                path_str,
                confirm_pubkey_on_device,
                host_device_path,
                auto_open_app,
                reply,
            } => {
                let result = parse(&path_str).and_then(|path| {
                    // Reuse only when it is the same device *and* the caller
                    // does not need an on-screen confirmation, which by
                    // definition has to reach the device.
                    if let Some(existing) = session
                        .as_ref()
                        .filter(|s| s.host_device_path == host_device_path)
                        .filter(|_| !confirm_pubkey_on_device)
                    {
                        if let Ok(pubkey) = existing.wallet.get_pubkey(&path, false) {
                            return Ok(pubkey.to_bytes());
                        }
                        // The cached handle is stale; fall through and rebuild.
                    }
                    session = None;
                    let attempt = |host: Option<&str>| {
                        establish_session(&path, confirm_pubkey_on_device, host)
                    };
                    let mut connected = attempt(host_device_path.as_deref());

                    // The Solana app may simply not be running. Once the user
                    // has unlocked with their PIN, auto-launch it for them via
                    // the BOLOS dashboard instead of erroring out with "open the
                    // Solana app", then retry across the USB re-enumeration that
                    // launching an app triggers. Best-effort: if the dashboard is
                    // unreachable we keep the original connect error. Declining
                    // the launch prompt on-device, though, is a real user
                    // decision — surface it.
                    if connected.is_err() && auto_open_app {
                        match dashboard::ensure_solana_app_open(host_device_path.as_deref()) {
                            Ok(_launched) => {
                                for _ in 0..20 {
                                    std::thread::sleep(std::time::Duration::from_millis(250));
                                    connected = attempt(host_device_path.as_deref());
                                    if connected.is_ok() {
                                        break;
                                    }
                                }
                            }
                            Err(e @ SignerError::UserRejected(_)) => return Err(e),
                            Err(e) => log::debug!(
                                "could not auto-open the Solana app ({e:?}); continuing"
                            ),
                        }
                    }

                    let (wallet, pubkey_bytes) = connected?;
                    session = Some(Session {
                        wallet,
                        host_device_path,
                    });
                    Ok(pubkey_bytes)
                });
                respond(&mut session, &reply, result);
            }

            DeviceCommand::SignTransactionMessage {
                path_str,
                message,
                reply,
            } => {
                let result = with_session(&mut session, &path_str, |wallet, path| {
                    wallet
                        .sign_message(path, &message)
                        .map(signature_bytes)
                        .map_err(map_rw_err)
                });
                respond(&mut session, &reply, result);
            }

            DeviceCommand::SignOffchainMessage {
                path_str,
                message,
                reply,
            } => {
                let result = with_session(&mut session, &path_str, |wallet, path| {
                    wallet
                        .sign_offchain_message(path, &message)
                        .map(signature_bytes)
                        .map_err(map_rw_err)
                });
                respond(&mut session, &reply, result);
            }

            DeviceCommand::IsAvailable { path_str, reply } => {
                let ok = with_session(&mut session, &path_str, |wallet, path| {
                    wallet.get_pubkey(path, false).map_err(map_rw_err)
                })
                .is_ok();
                respond(&mut session, &reply, ok);
            }

            DeviceCommand::IsAttached { reply } => {
                const LEDGER_VID: u16 = 0x2c97;
                let attached = hidapi::HidApi::new()
                    .map(|api| api.device_list().any(|d| d.vendor_id() == LEDGER_VID))
                    .unwrap_or(false);
                respond(&mut session, &reply, attached);
            }
        }
    }
}

/// Run `f` against the cached session, dropping it if the device errors.
///
/// Discarding the handle on error is what makes the next `connect` re-establish:
/// a wallet whose device was unplugged, locked, or switched out of the Solana app
/// never recovers, so holding on to it would turn one transient failure into a
/// permanently broken signer.
fn with_session<T>(
    session: &mut Option<Session>,
    path_str: &str,
    f: impl FnOnce(&Rc<LedgerWallet>, &DerivationPath) -> Result<T, SignerError>,
) -> Result<T, SignerError> {
    let path = DerivationPath::from_absolute_path_str(path_str)
        .map_err(|e| SignerError::ConfigError(format!("invalid derivation path: {e}")))?;
    let Some(active) = session.as_ref() else {
        return Err(SignerError::NotAvailable(
            "no Ledger session; connect first".to_string(),
        ));
    };
    let result = f(&active.wallet, &path);
    if result.is_err() {
        *session = None;
    }
    result
}

/// The OS HID path of a Ledger wallet's own device handle.
///
/// `solana-remote-wallet` 4.x makes `Device::path` and `Device::info`
/// crate-private, so the value that used to be read as
/// `Device::host_device_path` is recovered from the wallet's own `hidapi`
/// handle instead. Same string, same format — and the same one
/// [`dashboard::ensure_solana_app_open`] matches against.
fn hid_path(wallet: &LedgerWallet) -> Option<String> {
    let info = wallet.device.get_device_info().ok()?;
    info.path().to_str().ok().map(str::to_string)
}

/// Extract the 64 raw bytes of a `solana-remote-wallet` signature so it can be
/// rebuilt as the SDK-version-selected [`Signature`] type (byte-level bridge —
/// no cross-version type unification required).
///
/// Taken as `impl AsRef<[u8]>` rather than naming `solana_signature::Signature`:
/// under `sdk-v4` the `solana-signature` crate is bundled inside `solana-sdk`
/// and is not a direct dependency to name.
fn signature_bytes(sig: impl AsRef<[u8]>) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

/// Map `solana-remote-wallet` errors onto [`SignerError`], preserving the
/// user-rejection and device-absence cases the caller wants to distinguish.
fn map_rw_err(e: RemoteWalletError) -> SignerError {
    use solana_remote_wallet::ledger_error::LedgerError;
    match e {
        // Two distinct "cancel"s: the host-side `UserCancel`, and the device
        // returning APDU status 0x6985 (`LedgerError::UserCancel`) when the
        // user rejects on-screen. A real on-device decline is the latter.
        RemoteWalletError::UserCancel | RemoteWalletError::LedgerError(LedgerError::UserCancel) => {
            SignerError::UserRejected("request rejected on Ledger device".to_string())
        }
        RemoteWalletError::NoDeviceFound => {
            SignerError::NotAvailable("no Ledger device found".to_string())
        }
        // A HID-layer failure is usually *not* a disconnect. The common cause is
        // another process already holding the device: Ledger Live keeps its
        // handle for as long as it runs, and so does any wallet tool or stray
        // script that opened the device and never exited. Naming only the
        // disconnect sends the user to check the cable, which is the one thing
        // that is fine.
        RemoteWalletError::Hid(_) => SignerError::NotAvailable(
            "Ledger is not reachable. Either it was disconnected, or another application is \
             holding the device — quit Ledger Live and any other wallet software, then retry."
                .to_string(),
        ),
        // An unclassified protocol error means the transport answered but the
        // app-level command did not. Two different states produce it and the
        // error carries nothing that separates them:
        //
        //   1. The device is locked. Observed on a Nano Gen5 that auto-locked
        //      between operations: every call failed as `Protocol("Unknown error")`.
        //   2. Another process holds the device. Observed on a Nano Gen5 with
        //      Ledger Live running: enumeration succeeds, so this is not
        //      `NoDeviceFound`, and the handle opens, so it is not `Hid`, but no
        //      app-level command completes.
        //
        // Reporting either as a *signing* failure is misleading — nothing was
        // signed and nothing is wrong with the transaction. It is `NotAvailable`
        // for the same reason "no device" is. Since we cannot tell the two
        // apart here, the message names both remedies: claiming only "locked"
        // sends anyone with Ledger Live open to re-enter a PIN that was never
        // the problem.
        RemoteWalletError::Protocol(_) => {
            // `SignerError` Display and Debug are both redacted by design, and
            // `detail_string` is crate-private, so an external caller cannot
            // read the remedy out of the error. Log it: this particular detail
            // is device state, not secret material, and without it the user just
            // sees "Signer not available" with nothing to act on.
            log::warn!(
                "Ledger did not answer an app-level command. It is either locked, or another \
                 application is holding the device. Unlock it and open the Solana app, or quit \
                 Ledger Live and any other wallet software, then retry."
            );
            SignerError::NotAvailable(
                "Ledger did not answer. It is either locked — unlock it and open the Solana app — \
                 or another application is holding the device, so quit Ledger Live and any other \
                 wallet software. Then retry."
                    .to_string(),
            )
        }
        other => SignerError::SigningFailed(format!("Ledger device error: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// The actor-health statics are process-global, so the tests that drive
    /// them cannot run concurrently with each other.
    static HEALTH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset_actor_health() {
        COMPLETED.store(0, Ordering::SeqCst);
        ABANDONED_AT.store(u64::MAX, Ordering::SeqCst);
    }

    /// A device thread that accepts commands and never answers, which is what a
    /// Ledger left on a confirm screen looks like from the host.
    fn wedged_actor() -> (Sender<DeviceCommand>, Receiver<DeviceCommand>) {
        mpsc::channel()
    }

    fn connect_cmd(reply: Sender<Result<[u8; 32], SignerError>>) -> DeviceCommand {
        DeviceCommand::Connect {
            path_str: DEFAULT_DERIVATION_PATH.to_string(),
            confirm_pubkey_on_device: false,
            host_device_path: None,
            auto_open_app: false,
            reply,
        }
    }

    // ── F-1: actor timeouts ──

    #[test]
    fn a_command_times_out_instead_of_blocking_forever() {
        let _guard = HEALTH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_actor_health();
        // The receiver is held so `send` succeeds, but nothing ever serves it.
        // Before this timeout existed the call below never returned: the reply
        // channel used a plain blocking `recv()`, and the HID read the real
        // actor blocks in (`solana-remote-wallet`'s `Ledger::read` -> hidapi
        // `HidDevice::read`) has no timeout of its own.
        let (tx, _rx) = wedged_actor();
        let start = Instant::now();
        let err = request_on(&tx, Duration::from_millis(200), connect_cmd).unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(5), "must not hang");
        assert!(matches!(err, SignerError::NotAvailable(_)));
        assert!(
            err.detail_string().contains("did not respond"),
            "got: {}",
            err.detail_string()
        );
        reset_actor_health();
    }

    #[test]
    fn a_wedged_actor_fails_fast_instead_of_queueing_behind_it() {
        let _guard = HEALTH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_actor_health();
        let (tx, _rx) = wedged_actor();
        // First caller gives up after its timeout.
        let _ = request_on(&tx, Duration::from_millis(200), connect_cmd);
        // The second must not wait its own full timeout: the actor is a single
        // serialized thread, so it cannot serve anyone until the stuck exchange
        // resolves. Without this, one stalled prompt degrades the whole process
        // one timeout at a time.
        let start = Instant::now();
        let err = request_on(&tx, Duration::from_secs(30), connect_cmd).unwrap_err();
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "second call waited {:?}; it should have failed fast",
            start.elapsed()
        );
        assert!(
            err.detail_string().contains("still blocked"),
            "got: {}",
            err.detail_string()
        );
        reset_actor_health();
    }

    #[test]
    fn the_actor_recovers_once_it_completes_a_command() {
        let _guard = HEALTH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_actor_health();
        let (tx, _rx) = wedged_actor();
        let _ = request_on(&tx, Duration::from_millis(200), connect_cmd);
        assert!(check_actor_responsive().is_err(), "should read as wedged");
        // The user finally pressed the button: the actor finishes the stuck
        // command and bumps its completion count. Normal service must resume
        // without anyone reconnecting or restarting the process.
        COMPLETED.fetch_add(1, Ordering::SeqCst);
        assert!(check_actor_responsive().is_ok(), "should have recovered");
        assert_eq!(
            ABANDONED_AT.load(Ordering::SeqCst),
            u64::MAX,
            "the wedge mark must be cleared, not merely stepped over"
        );
        reset_actor_health();
    }

    #[test]
    fn an_abandoned_reply_drops_the_cached_session() {
        let _guard = HEALTH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_actor_health();
        // A caller that timed out has dropped its receiver. The actor notices
        // when it finally answers, and must discard the session: that command
        // may have left the device mid-exchange, so the next connect has to
        // re-establish rather than reuse the handle.
        let (reply_tx, reply_rx) = mpsc::channel::<bool>();
        drop(reply_rx);
        let mut session: Option<Session> = None;
        // Stand-in for a live session; `respond` only ever sets it to `None`.
        let before = COMPLETED.load(Ordering::SeqCst);
        respond(&mut session, &reply_tx, true);
        assert!(session.is_none(), "session must be dropped");
        assert_eq!(
            COMPLETED.load(Ordering::SeqCst),
            before + 1,
            "completion must be counted even when the caller gave up"
        );
        reset_actor_health();
    }

    #[test]
    fn the_two_timeout_tiers_are_ordered_and_bounded() {
        // A probe that cannot involve the user must not inherit the
        // wait-for-a-human budget, and the signing default must stay inside a
        // Ledger's ten-minute auto-lock: past that the prompt is gone and no
        // answer is coming.
        assert!(FAST_COMMAND_TIMEOUT < DEFAULT_SIGNING_TIMEOUT);
        assert!(FAST_COMMAND_TIMEOUT >= Duration::from_secs(5));
        assert!(DEFAULT_SIGNING_TIMEOUT <= Duration::from_secs(600));
        assert_eq!(
            LedgerConfig::default().signing_timeout,
            DEFAULT_SIGNING_TIMEOUT
        );
    }

    #[test]
    fn auto_open_app_defaults_on_and_is_overridable() {
        // Default true keeps the interactive CLI behaviour these tests were
        // written against; the point of the option is unattended callers.
        assert!(LedgerConfig::default().auto_open_app);
        let quiet = LedgerConfig {
            auto_open_app: false,
            ..LedgerConfig::default()
        };
        assert!(!quiet.auto_open_app);
    }

    // NOTE: signing paths require a physical device and are covered by the
    // hardware integration test (see `tests/test_ledger_integration.rs`), not
    // here — these unit tests only cover the pure logic that needs no device.

    // ── F-3: signature binding is what closes the device-swap race ──

    /// Two distinct keys, standing in for two physically different Ledgers.
    fn device_key(seed: u8) -> (crate::sdk_adapter::Keypair, Pubkey) {
        let kp = crate::sdk_adapter::keypair_from_seed(&[seed; 32]).expect("valid seed");
        let pubkey = crate::sdk_adapter::keypair_pubkey(&kp);
        (kp, pubkey)
    }

    #[test]
    fn a_swapped_device_is_caught_as_a_verification_failure() {
        // The race this closes: `LedgerSigner` caches a pubkey at connect, but
        // the actor's cached session is keyed on the host path, not on the
        // signer. If a second `connect` re-points the session at a different
        // device, an existing signer's next command runs against *that* device.
        //
        // The signature then comes back from the wrong key. Because every
        // signature is verified against the pubkey cached at connect, and never
        // against whatever the device reports now, this surfaces as a clean
        // rejection instead of a wrong-key signature being attached.
        let (device_a, pubkey_a) = device_key(1);
        let (device_b, pubkey_b) = device_key(2);
        assert_ne!(pubkey_a, pubkey_b);

        let envelope = ledger_offchain_envelope(&pubkey_a, b"transfer 1 SOL").unwrap();
        // The swapped-in device signs the bytes we sent, with its own key.
        let from_b = crate::sdk_adapter::keypair_sign_message(&device_b, &envelope);

        let err = crate::signature_util::verify_or_reject(&from_b, &pubkey_a, &envelope)
            .expect_err("a signature from a swapped device must never be attached");
        assert!(matches!(err, SignerError::SigningFailed(_)));

        // Control: the device we actually connected to is accepted.
        let from_a = crate::sdk_adapter::keypair_sign_message(&device_a, &envelope);
        assert!(crate::signature_util::verify_or_reject(&from_a, &pubkey_a, &envelope).is_ok());
    }

    #[test]
    fn a_corrupted_signature_is_rejected_on_the_offchain_path() {
        // Transport corruption on the off-chain path. The bytes verified are the
        // envelope, not the payload, which is the whole reason this check has to
        // be built from `ledger_offchain_envelope` and not from the raw message.
        let (device, pubkey) = device_key(3);
        let envelope = ledger_offchain_envelope(&pubkey, b"hello").unwrap();
        let good = crate::sdk_adapter::keypair_sign_message(&device, &envelope);
        assert!(crate::signature_util::verify_or_reject(&good, &pubkey, &envelope).is_ok());

        let mut raw = signature_bytes(good);
        raw[0] ^= 0x01;
        let corrupted = Signature::from(raw);
        assert!(
            crate::signature_util::verify_or_reject(&corrupted, &pubkey, &envelope).is_err(),
            "a single flipped bit must fail verification"
        );
    }

    #[test]
    fn a_corrupted_signature_is_rejected_on_the_transaction_path() {
        // Same guarantee on the transaction path, over the exact bytes that
        // cross to the device: `tx.message.serialize()`.
        let (device, pubkey) = device_key(4);
        let tx = crate::test_util::create_test_transaction(&pubkey);
        let message = tx.message.serialize();
        let good = crate::sdk_adapter::keypair_sign_message(&device, &message);
        assert!(crate::signature_util::verify_or_reject(&good, &pubkey, &message).is_ok());

        let mut raw = signature_bytes(good);
        raw[63] ^= 0x80;
        let corrupted = Signature::from(raw);
        assert!(
            crate::signature_util::verify_or_reject(&corrupted, &pubkey, &message).is_err(),
            "a single flipped bit must fail verification"
        );
    }

    #[test]
    fn both_signing_paths_verify_before_returning() {
        // The tests above prove the predicate rejects bad signatures. They
        // cannot prove the signing paths still *call* it, and that is the
        // failure that would actually ship: a refactor dropping the check leaves
        // every test above green. So assert it against the source.
        //
        // Neither call is behind a `cfg`, and no other code path returns a
        // signature: the dashboard is reachable only from `Connect`, which
        // returns a pubkey.
        let src = include_str!("mod.rs");
        // Split off this test module first: its own source mentions the call,
        // and counting that would let the guard satisfy itself.
        let production = src
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .expect("module has a test section");
        let verify_calls = production
            .matches("verify_or_reject(&signature, &self.pubkey")
            .count();
        assert_eq!(
            verify_calls, 2,
            "expected exactly one verify_or_reject in sign_message and one in \
             sign_transaction; found {verify_calls}"
        );
        for path in ["async fn sign_message", "async fn sign_transaction"] {
            let body = production.split(path).nth(1).expect("signing fn present");
            let end = body.find("\n    }").expect("fn body terminates");
            assert!(
                body[..end].contains("verify_or_reject"),
                "{path} must verify the device signature before returning it"
            );
        }
    }

    #[test]
    fn default_derivation_path_is_solana_bip44() {
        let path = DerivationPath::from_absolute_path_str(DEFAULT_DERIVATION_PATH);
        assert!(path.is_ok(), "default derivation path must parse");
    }

    #[test]
    fn signature_bytes_roundtrips() {
        // The SDK-selected `Signature` stands in for `solana-remote-wallet`'s:
        // both are `solana-signature` types, and the bridge is byte-level, so
        // this exercises exactly the conversion the device path performs.
        let raw = [7u8; 64];
        let sig = Signature::from(raw);
        assert_eq!(signature_bytes(sig), raw);
    }

    #[test]
    fn user_cancel_maps_to_user_rejected() {
        let err = map_rw_err(RemoteWalletError::UserCancel);
        assert!(matches!(err, SignerError::UserRejected(_)));
    }

    #[test]
    fn no_device_maps_to_not_available() {
        let err = map_rw_err(RemoteWalletError::NoDeviceFound);
        assert!(matches!(err, SignerError::NotAvailable(_)));
    }

    #[test]
    fn offchain_envelope_matches_the_ledger_app_layout() {
        // Byte-exact against LedgerHQ/app-solana's `parse_offchain_message_header`.
        // Pinning the layout matters more than usual here: the obvious choice —
        // `solana_offchain_message`'s serializer — produces a *different*
        // envelope that the device rejects, so a future refactor "simplifying"
        // this back to the crate would silently break signing again.
        let signer = Pubkey::from([7u8; 32]);
        let payload = b"hello";
        let env = ledger_offchain_envelope(&signer, payload).unwrap();

        assert_eq!(&env[0..16], b"\xffsolana offchain", "signing domain");
        assert_eq!(env[16], 0, "header version");
        assert_eq!(&env[17..49], &[0u8; 32], "application domain: not provided");
        assert_eq!(env[49], 0, "format 0 = RestrictedAscii for printable ASCII");
        assert_eq!(env[50], 1, "exactly one signer");
        assert_eq!(&env[51..83], &[7u8; 32], "the signer's pubkey");
        assert_eq!(&env[83..85], &5u16.to_le_bytes(), "length, little-endian");
        assert_eq!(&env[85..], payload, "message body");
        assert_eq!(env.len(), 85 + payload.len());
    }

    #[test]
    fn offchain_envelope_picks_the_format_from_the_payload() {
        let signer = Pubkey::from([1u8; 32]);
        // Printable ASCII -> RestrictedAscii.
        let ascii = ledger_offchain_envelope(&signer, b"plain text").unwrap();
        assert_eq!(ascii[49], 0);
        // Valid UTF-8 that is not printable ASCII -> LimitedUtf8. The app
        // rejects format 2, so this is the only other value it will take.
        let utf8 = ledger_offchain_envelope(&signer, "café ☕".as_bytes()).unwrap();
        assert_eq!(utf8[49], 1);
        // Not UTF-8 at all: refused locally rather than at the device.
        let err = ledger_offchain_envelope(&signer, &[0xff, 0xfe]).unwrap_err();
        assert!(matches!(err, SignerError::ConfigError(_)));
    }

    #[test]
    fn offchain_envelope_rejects_payloads_the_device_would_reject() {
        let signer = Pubkey::from([2u8; 32]);
        // The app rejects `header.length == 0`.
        assert!(ledger_offchain_envelope(&signer, b"").is_err());
        // At the limit it is accepted; one byte over it is not. The binding cap
        // comes from solana-remote-wallet's send-side guard, not the device.
        let at_limit = vec![b'a'; MAX_OFFCHAIN_PAYLOAD_LEN];
        assert!(ledger_offchain_envelope(&signer, &at_limit).is_ok());
        let over = vec![b'a'; MAX_OFFCHAIN_PAYLOAD_LEN + 1];
        assert!(ledger_offchain_envelope(&signer, &over).is_err());
        // And the whole envelope still fits what remote-wallet will send.
        assert_eq!(
            ledger_offchain_envelope(&signer, &at_limit).unwrap().len(),
            1215
        );
    }

    #[test]
    fn locked_device_maps_to_not_available_and_says_so() {
        // What a locked device actually produces, observed on a Nano Gen5 that
        // auto-locked mid-session: the transport answers, the app-level command
        // does not, and it arrives as an unclassified protocol error. It must not
        // be reported as a signing failure — nothing was signed.
        let err = map_rw_err(RemoteWalletError::Protocol("Unknown error"));
        assert!(matches!(err, SignerError::NotAvailable(_)));
        // The caller cannot see the device screen, so the remedy has to be in
        // the message. `detail_string` is what surfaces it (Display is redacted).
        assert!(
            err.detail_string().contains("locked"),
            "a locked device must be described as locked, got: {}",
            err.detail_string()
        );
    }

    #[test]
    fn unclassified_protocol_error_also_names_the_busy_device() {
        // The same `Protocol(_)` arm fires when another process holds the device
        // — observed on a Nano Gen5 with Ledger Live running, and again with a
        // stray script that had opened the device and not exited. Enumeration
        // succeeds and the handle opens, so neither `NoDeviceFound` nor `Hid`
        // catches it, and nothing in the error separates it from a locked
        // device. A message that offers only "unlock it" therefore sends the
        // user to re-enter a PIN that was never the problem, which is exactly
        // the loop this arm has to break.
        let err = map_rw_err(RemoteWalletError::Protocol("Unknown error"));
        let detail = err.detail_string();
        assert!(
            detail.contains("another application"),
            "a busy device must be offered as a cause, got: {detail}"
        );
        assert!(
            detail.contains("Ledger Live"),
            "the remedy has to name the usual culprit, got: {detail}"
        );
    }

    #[test]
    fn hid_error_points_at_a_busy_device_not_just_the_cable() {
        // A HID-layer failure is far more often a held handle than a real
        // disconnect. Reporting only the disconnect sends the user to check the
        // one thing that is fine.
        let err = map_rw_err(RemoteWalletError::Hid("device open failed".to_string()));
        assert!(matches!(err, SignerError::NotAvailable(_)));
        let detail = err.detail_string();
        assert!(
            detail.contains("another application"),
            "a held HID handle must be offered as a cause, got: {detail}"
        );
    }

    #[test]
    fn connect_without_device_fails_cleanly() {
        // Contract: with no usable Ledger, connect returns an error cleanly and
        // never hangs or panics. We accept any Err (the exact variant depends on
        // the host's HID subsystem — e.g. NotAvailable when absent, but a CI
        // runner without libhidapi may surface something else). If a device *is*
        // attached, connect succeeds and there is nothing to assert.
        match LedgerSigner::connect(None, false, None) {
            Ok(_) | Err(_) => {}
        }
    }
}
