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
use std::sync::mpsc::{self, Receiver, Sender};

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

/// Requests sent to the device-actor thread. Each carries a one-shot reply
/// channel the actor uses to return the result.
enum DeviceCommand {
    /// Establish (or reuse) a device session and read the pubkey at `path_str`.
    Connect {
        path_str: String,
        confirm_pubkey_on_device: bool,
        host_device_path: Option<String>,
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
        let path_str = derivation_path
            .unwrap_or(DEFAULT_DERIVATION_PATH)
            .to_string();
        // Validate before troubling the device, so a typo is a clear config
        // error rather than an obscure APDU failure.
        DerivationPath::from_absolute_path_str(&path_str)
            .map_err(|e| SignerError::ConfigError(format!("invalid derivation path: {e}")))?;

        let host_device_path = host_device_path.map(str::to_string);
        let pubkey_bytes = request_on(device_channel(), |reply| DeviceCommand::Connect {
            path_str: path_str.clone(),
            confirm_pubkey_on_device,
            host_device_path,
            reply,
        })?;

        Ok(Self {
            pubkey: Pubkey::from(pubkey_bytes),
            path_str,
        })
    }

    /// Is a Ledger attached, whether or not it is usable right now?
    ///
    /// Answers without requiring the device to be unlocked or the Solana app to
    /// be open, so a caller can tell "no hardware" apart from "hardware present
    /// but not ready" — which are very different things to report to a user.
    /// Goes through the device thread; see [`DEVICE_THREAD`].
    pub fn is_attached() -> bool {
        let cmd_tx = device_channel();
        let (reply_tx, reply_rx) = mpsc::channel();
        if cmd_tx
            .send(DeviceCommand::IsAttached { reply: reply_tx })
            .is_err()
        {
            return false;
        }
        reply_rx.recv().unwrap_or(false)
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
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(device_channel(), |reply| {
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

    async fn is_available(&self) -> bool {
        let path_str = self.path_str.clone();
        tokio::task::spawn_blocking(move || {
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
            reply_rx.recv().unwrap_or(false)
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
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(device_channel(), |reply| {
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

/// Send a command to the device actor and block for its reply. Called from
/// inside `spawn_blocking`, with a `cmd_tx` cloned out of the signer.
fn request_on<T: Send + 'static>(
    cmd_tx: &Sender<DeviceCommand>,
    build: impl FnOnce(Sender<Result<T, SignerError>>) -> DeviceCommand,
) -> Result<T, SignerError> {
    let (reply_tx, reply_rx) = mpsc::channel();
    cmd_tx.send(build(reply_tx)).map_err(|_| {
        SignerError::NotAvailable("Ledger device thread is not running".to_string())
    })?;
    reply_rx
        .recv()
        .map_err(|_| SignerError::NotAvailable("Ledger device thread stopped".to_string()))?
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
                    if connected.is_err() {
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
                let _ = reply.send(result);
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
                let _ = reply.send(result);
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
                let _ = reply.send(result);
            }

            DeviceCommand::IsAvailable { path_str, reply } => {
                let ok = with_session(&mut session, &path_str, |wallet, path| {
                    wallet.get_pubkey(path, false).map_err(map_rw_err)
                })
                .is_ok();
                let _ = reply.send(ok);
            }

            DeviceCommand::IsAttached { reply } => {
                const LEDGER_VID: u16 = 0x2c97;
                let attached = hidapi::HidApi::new()
                    .map(|api| api.device_list().any(|d| d.vendor_id() == LEDGER_VID))
                    .unwrap_or(false);
                let _ = reply.send(attached);
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
        RemoteWalletError::Hid(_) => {
            SignerError::NotAvailable("Ledger device disconnected or unavailable".to_string())
        }
        // A locked device answers the transport but refuses the app-level
        // command, which surfaces as an unclassified protocol error. Observed on
        // a Nano Gen5 that auto-locked between operations: every call failed as
        // `Protocol("Unknown error")`. Categorising that as a *signing* failure
        // is actively misleading — nothing was signed and nothing is wrong with
        // the transaction; the user needs to enter their PIN. It is
        // `NotAvailable` for the same reason "no device" is, and the message has
        // to say so, because the caller cannot see the device screen.
        RemoteWalletError::Protocol(_) => {
            // `SignerError` Display and Debug are both redacted by design, and
            // `detail_string` is crate-private, so an external caller cannot
            // read the remedy out of the error. Log it: this particular detail
            // is device state, not secret material, and without it the user just
            // sees "Signer not available" with nothing to act on.
            log::warn!(
                "Ledger did not answer an app-level command; it is most likely locked. \
                 Unlock the device and open the Solana app, then retry."
            );
            SignerError::NotAvailable(
                "Ledger did not answer — it is most likely locked. Unlock it (and open the Solana \
                 app) and retry."
                    .to_string(),
            )
        }
        other => SignerError::SigningFailed(format!("Ledger device error: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: signing paths require a physical device and are covered by the
    // hardware integration test (see `tests/test_ledger_integration.rs`), not
    // here — these unit tests only cover the pure logic that needs no device.

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
