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
//! Currently gated to `sdk-v3` (see the `compile_error!` in `lib.rs`): the
//! solana-* crate versions `solana-remote-wallet` pins line up with the v3 SDK.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;

use solana_derivation_path::DerivationPath;
use solana_remote_wallet::remote_wallet::{
    initialize_wallet_manager, RemoteWallet, RemoteWalletError,
};

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, Transaction};
use crate::traits::{SignTransactionResult, SolanaSigner};
use crate::transaction_util::TransactionUtil;

/// Default Solana BIP44 derivation path: `m/44'/501'/0'/0'`.
pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/501'/0'/0'";

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
    /// Requires the Ledger to be plugged in, unlocked, and running the Solana
    /// app. On Linux, the appropriate `udev` rules must be installed.
    pub fn connect(
        derivation_path: Option<&str>,
        confirm_pubkey_on_device: bool,
    ) -> Result<Self, SignerError> {
        let path_str = derivation_path
            .unwrap_or(DEFAULT_DERIVATION_PATH)
            .to_string();

        let (setup_tx, setup_rx) = mpsc::channel::<Result<[u8; 32], SignerError>>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<DeviceCommand>();

        let worker = std::thread::Builder::new()
            .name("ledger-device".to_string())
            .spawn(move || device_actor(path_str, confirm_pubkey_on_device, setup_tx, cmd_rx))
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

    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let message = message.to_vec();
        let cmd_tx = self.cmd_tx.clone();
        let sig_bytes: [u8; 64] = tokio::task::spawn_blocking(move || {
            request_on(&cmd_tx, |reply| DeviceCommand::SignOffchainMessage {
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
    setup_tx: Sender<Result<[u8; 32], SignerError>>,
    cmd_rx: Receiver<DeviceCommand>,
) {
    // ── Connect ────────────────────────────────────────────────────────────
    let connected = (|| {
        let path = DerivationPath::from_absolute_path_str(&path_str)
            .map_err(|e| SignerError::ConfigError(format!("invalid derivation path: {e}")))?;

        let manager = initialize_wallet_manager().map_err(map_rw_err)?;
        let count = manager.update_devices().map_err(map_rw_err)?;
        if count == 0 {
            return Err(SignerError::NotAvailable(
                "no Ledger device found (plug in, unlock, and open the Solana app)".to_string(),
            ));
        }

        let info = manager
            .list_devices()
            .into_iter()
            .find(|d| d.model.to_lowercase().contains("ledger"))
            .ok_or_else(|| SignerError::NotAvailable("no Ledger device found".to_string()))?;

        let ledger = manager
            .get_ledger(&info.host_device_path)
            .map_err(map_rw_err)?;
        let pubkey = ledger
            .get_pubkey(&path, confirm_pubkey_on_device)
            .map_err(map_rw_err)?;

        Ok::<_, SignerError>((ledger, path, pubkey.to_bytes()))
    })();

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

/// Extract the 64 raw bytes of a `solana-remote-wallet` signature so it can be
/// rebuilt as the SDK-version-selected [`Signature`] type (byte-level bridge —
/// no cross-version type unification required).
fn signature_bytes(sig: solana_signature::Signature) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

/// Map `solana-remote-wallet` errors onto [`SignerError`], preserving the
/// user-rejection and device-absence cases the caller wants to distinguish.
fn map_rw_err(e: RemoteWalletError) -> SignerError {
    match e {
        RemoteWalletError::UserCancel => {
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
        let raw = [7u8; 64];
        let sig = solana_signature::Signature::from(raw);
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
    fn connect_without_device_errors_not_available() {
        // No Ledger attached in CI: connect must fail cleanly (NotAvailable),
        // never hang or panic. (If a device *is* attached this is skipped.)
        match LedgerSigner::connect(None, false) {
            Err(SignerError::NotAvailable(_)) => {}
            Err(other) => panic!("expected NotAvailable, got {other:?}"),
            Ok(_) => { /* a device is plugged in; nothing to assert here */ }
        }
    }
}
