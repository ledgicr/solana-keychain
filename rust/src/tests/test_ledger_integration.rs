//! Ledger hardware-wallet integration tests.
//!
//! Unlike the other backends, Ledger has no remote API or credentials — it
//! needs a **physical device** plugged in, unlocked, and running the Solana
//! app. These tests are therefore gated behind `integration-tests` *and* skip
//! themselves at runtime when no device is connected, so they are safe to leave
//! in the normal `integration-tests` matrix.
//!
//! Run manually with a device attached:
//! ```bash
//! just rust-test-ledger
//! ```

#[cfg(feature = "ledger")]
#[cfg(test)]
mod tests {
    use crate::ledger::LedgerSigner;
    use crate::traits::{SolanaSigner, TransactionSigner};

    /// `connect(None, false, None)` either succeeds (device present) or returns a
    /// clean `NotAvailable`/`UserRejected` error — it must never hang or panic.
    fn try_connect() -> Option<LedgerSigner> {
        match LedgerSigner::connect(None, false, None) {
            Ok(signer) => Some(signer),
            Err(e) => {
                // Say *why*, and surface the detail. Skipping is the point of
                // these tests in CI, but a device that is plugged in and merely
                // locked skips for a completely different reason than no device
                // at all, and "no usable Ledger device" hid that distinction --
                // which cost real debugging time when a Gen5 auto-locked
                // mid-session and every test quietly reported a pass.
                eprintln!(
                    "skipping Ledger hardware test -- could not connect: {}",
                    e.detail_string()
                );
                None
            }
        }
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_ledger_pubkey_and_availability() {
        let Some(signer) = try_connect() else { return };
        assert!(
            signer.is_available().await,
            "device should report available"
        );
        // A real Solana pubkey is 32 bytes and never the zero address.
        assert_ne!(signer.pubkey(), Default::default());
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_ledger_sign_offchain_message() {
        let Some(signer) = try_connect() else { return };
        // Requires a press on the device to approve.
        let message = b"solana-keychain ledger integration test";
        let signature = signer
            .sign_message(message)
            .await
            .expect("device should sign the off-chain message");
        assert_eq!(signature.as_ref().len(), 64);
        // `sign_message` signs the off-chain *envelope*, not the raw bytes, so
        // verify against the serialized `OffchainMessage` (see the sign_message
        // docs on the Ledger backend).
        let serialized = solana_offchain_message::OffchainMessage::new(0, message)
            .and_then(|m| m.serialize())
            .expect("valid off-chain message");
        assert!(
            signature.verify(&signer.pubkey().to_bytes(), &serialized),
            "signature must verify against the serialized off-chain message"
        );
    }

    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_ledger_sign_transaction() {
        use crate::test_util::create_test_transaction;

        let Some(signer) = try_connect() else { return };
        let mut tx = create_test_transaction(&signer.pubkey());
        // Requires a press on the device to approve.
        let result = signer
            .sign_transaction(&mut tx)
            .await
            .expect("device should sign the transaction");
        let (_serialized, signature) = result.into_signed_transaction();
        assert_eq!(signature.as_ref().len(), 64);
        assert_eq!(tx.signatures[0], signature);
    }
}
