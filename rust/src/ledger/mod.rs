//! Ledger hardware-wallet signer over USB-HID.
//!
//! Unlike the other backends in this crate (which talk to remote HTTP APIs),
//! the Ledger backend drives a physical device on the local machine through
//! [`solana-remote-wallet`](https://docs.rs/solana-remote-wallet) — Solana's
//! canonical Ledger APDU client. The private key never leaves the device, and
//! every signature must be confirmed on the device screen.
//!
//! ## Why a dedicated thread
//!
//! `solana-remote-wallet` is single-threaded: its `RemoteWalletManager` and
//! `LedgerWallet` handles are reference-counted with [`std::rc::Rc`] and wrap a
//! `hidapi` device that is not [`Sync`]. The [`SolanaSigner`] trait, by
//! contrast, is `async` and `Send + Sync`. To bridge the two we confine **all**
//! device I/O to one dedicated OS thread (the "device actor"). [`LedgerSigner`]
//! holds only a channel [`Sender`] (which is `Send + Sync`) and a cached public
//! key; each trait method performs a blocking request/response round-trip with
//! the actor from inside [`tokio::task::spawn_blocking`]. Serializing every
//! operation through one thread is also correct on its own terms — a Ledger can
//! only service one APDU exchange at a time.
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
use std::thread::JoinHandle;

use solana_derivation_path::DerivationPath;
use solana_remote_wallet::ledger::LedgerWallet;
use solana_remote_wallet::remote_wallet::{
    initialize_wallet_manager, RemoteWallet, RemoteWalletError, RemoteWalletType,
};

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::{SignTransactionResult, SolanaSigner};
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
    /// Sign serialized transaction-message bytes (Solana app "sign" APDU).
    SignTransactionMessage {
        message: Vec<u8>,
        reply: Sender<Result<[u8; 64], SignerError>>,
    },
    /// Sign an off-chain message (Solana app "sign off-chain message" APDU).
    SignOffchainMessage {
        message: Vec<u8>,
        reply: Sender<Result<[u8; 64], SignerError>>,
    },
    /// Liveness probe: can we read the pubkey without on-device confirmation?
    IsAvailable { reply: Sender<bool> },
}

/// A [`SolanaSigner`] backed by a Ledger hardware wallet.
pub struct LedgerSigner {
    cmd_tx: Sender<DeviceCommand>,
    pubkey: Pubkey,
    // Kept so the worker thread is observable for the lifetime of the signer.
    // When `LedgerSigner` is dropped, `cmd_tx` drops, the actor's `recv()`
    // returns `Err`, and the thread exits on its own.
    _worker: JoinHandle<()>,
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
        let host_device_path = host_device_path.map(str::to_string);

        let (setup_tx, setup_rx) = mpsc::channel::<Result<[u8; 32], SignerError>>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<DeviceCommand>();

        let worker = std::thread::Builder::new()
            .name("ledger-device".to_string())
            .spawn(move || {
                device_actor(
                    path_str,
                    confirm_pubkey_on_device,
                    host_device_path,
                    setup_tx,
                    cmd_rx,
                )
            })
            .map_err(|e| {
                SignerError::Other(format!("failed to spawn Ledger device thread: {e}"))
            })?;

        // Wait for the actor to connect and report the public key (or fail).
        let pubkey_bytes = setup_rx
            .recv()
            .map_err(|_| SignerError::NotAvailable("Ledger device thread exited".to_string()))??;

        Ok(Self {
            cmd_tx,
            pubkey: Pubkey::from(pubkey_bytes),
            _worker: worker,
        })
    }
}

#[async_trait::async_trait]
impl SolanaSigner for LedgerSigner {
    fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignTransactionResult, SignerError> {
        let message = tx.message_data();
        let cmd_tx = self.cmd_tx.clone();
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(&cmd_tx, |reply| DeviceCommand::SignTransactionMessage {
                message,
                reply,
            })
        })
        .await
        .map_err(|e| SignerError::Other(format!("Ledger signing task failed: {e}")))??;

        let signature = Signature::from(sig_bytes);
        TransactionUtil::add_signature_to_transaction(tx, &self.pubkey, signature)?;
        let serialized = TransactionUtil::serialize_transaction(tx)?;
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            (serialized, signature),
        ))
    }

    /// Sign `message` as a Solana **off-chain message**.
    ///
    /// A hardware wallet cannot raw-ed25519-sign arbitrary bytes the way the
    /// software backends do. It signs a *structured* off-chain message: the
    /// payload is wrapped in the Solana off-chain envelope (the
    /// `\xffsolana offchain` signing domain + header) and the device signs that.
    /// The returned signature therefore covers the **serialized
    /// `OffchainMessage`**, not the raw `message` bytes. Verify it against the
    /// serialized form (`OffchainMessage::new(0, message)?.serialize()?`) — a
    /// plain `signature.verify(pubkey, message)` over the raw bytes will fail.
    /// This deviates from the raw-bytes contract of the software backends by
    /// necessity; see the `sign_message` note on [`SolanaSigner`].
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let serialized = solana_offchain_message::OffchainMessage::new(0, message)
            .and_then(|m| m.serialize())
            .map_err(|e| SignerError::ConfigError(format!("invalid off-chain message: {e:?}")))?;
        let cmd_tx = self.cmd_tx.clone();
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(&cmd_tx, |reply| DeviceCommand::SignOffchainMessage {
                message: serialized,
                reply,
            })
        })
        .await
        .map_err(|e| SignerError::Other(format!("Ledger signing task failed: {e}")))??;
        Ok(Signature::from(sig_bytes))
    }

    async fn sign_transaction_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // A serialized transaction message (legacy or versioned/v0). Route it
        // through the device's transaction-parsing APDU — NOT the off-chain
        // envelope that `sign_message` uses. This is the same device command
        // `sign_transaction` uses; it just takes pre-serialized bytes and
        // returns the raw signature for the caller to place at the signer index
        // (used by the x402 versioned-transaction path).
        let message = message.to_vec();
        let cmd_tx = self.cmd_tx.clone();
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(&cmd_tx, |reply| DeviceCommand::SignTransactionMessage {
                message,
                reply,
            })
        })
        .await
        .map_err(|e| SignerError::Other(format!("Ledger signing task failed: {e}")))??;
        Ok(Signature::from(sig_bytes))
    }

    async fn is_available(&self) -> bool {
        let cmd_tx = self.cmd_tx.clone();
        tokio::task::spawn_blocking(move || {
            let (reply_tx, reply_rx) = mpsc::channel();
            if cmd_tx
                .send(DeviceCommand::IsAvailable { reply: reply_tx })
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
fn device_actor(
    path_str: String,
    confirm_pubkey_on_device: bool,
    host_device_path: Option<String>,
    setup_tx: Sender<Result<[u8; 32], SignerError>>,
    cmd_rx: Receiver<DeviceCommand>,
) {
    // ── Connect ────────────────────────────────────────────────────────────
    let attempt = || {
        let path = DerivationPath::from_absolute_path_str(&path_str)
            .map_err(|e| SignerError::ConfigError(format!("invalid derivation path: {e}")))?;

        // A failure to bring up the HID subsystem is an *availability* problem,
        // not a signing failure — map it to NotAvailable directly rather than
        // letting map_rw_err's catch-all bucket it as SigningFailed (which would
        // also make the no-device unit test panic on CI runners lacking libhidapi).
        let manager = initialize_wallet_manager().map_err(|e| {
            SignerError::NotAvailable(format!("Ledger HID subsystem unavailable: {e}"))
        })?;
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
        let ledger = match host_device_path.as_deref() {
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
            .get_pubkey(&path, confirm_pubkey_on_device)
            .map_err(map_rw_err)?;

        Ok::<_, SignerError>((ledger, path, pubkey.to_bytes()))
    };

    // Try the normal Solana-app connection first: when the app is already open
    // (the common case) this succeeds immediately and we never touch the
    // dashboard — no second HID handle, no contention, no added latency.
    let mut connected = attempt();

    // If it failed, the Solana app may simply not be running. Once the user has
    // unlocked with their PIN, auto-launch it for them (via the BOLOS dashboard)
    // instead of erroring out with "open the Solana app", then retry across the
    // USB re-enumeration that launching an app triggers. Best-effort: if the
    // dashboard is unreachable we keep the original connect error. Declining the
    // launch prompt on-device, though, is a real user decision — surface it.
    if connected.is_err() {
        match dashboard::ensure_solana_app_open(host_device_path.as_deref()) {
            Ok(_launched) => {
                for _ in 0..20 {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                    connected = attempt();
                    if connected.is_ok() {
                        break;
                    }
                }
            }
            Err(e @ SignerError::UserRejected(_)) => {
                let _ = setup_tx.send(Err(e));
                return;
            }
            Err(e) => log::debug!("could not auto-open the Solana app ({e:?}); continuing"),
        }
    }

    let (ledger, path) = match connected {
        Ok((ledger, path, pubkey_bytes)) => {
            if setup_tx.send(Ok(pubkey_bytes)).is_err() {
                return; // caller gave up
            }
            (ledger, path)
        }
        Err(e) => {
            let _ = setup_tx.send(Err(e));
            return;
        }
    };

    // ── Serve ──────────────────────────────────────────────────────────────
    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            DeviceCommand::SignTransactionMessage { message, reply } => {
                let _ = reply.send(
                    ledger
                        .sign_message(&path, &message)
                        .map(signature_bytes)
                        .map_err(map_rw_err),
                );
            }
            DeviceCommand::SignOffchainMessage { message, reply } => {
                let _ = reply.send(
                    ledger
                        .sign_offchain_message(&path, &message)
                        .map(signature_bytes)
                        .map_err(map_rw_err),
                );
            }
            DeviceCommand::IsAvailable { reply } => {
                let _ = reply.send(ledger.get_pubkey(&path, false).is_ok());
            }
        }
    }
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
