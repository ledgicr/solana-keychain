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

    /// Connect, or skip when there is genuinely no device.
    ///
    /// Skipping is deliberate: CI has no Ledger and these tests must not fail
    /// there. But it is only legitimate when no device is attached. If one *is*
    /// attached and we still cannot connect — locked, wrong app, another process
    /// holding it — that is an operator problem, and panicking is the honest
    /// outcome. Reporting it as a pass is how a locked Gen5 previously made this
    /// whole suite look green while testing nothing.
    fn try_connect() -> Option<LedgerSigner> {
        match LedgerSigner::connect(None, false, None) {
            Ok(signer) => Some(signer),
            Err(e) if !LedgerSigner::is_attached() => {
                eprintln!(
                    "skipping Ledger hardware test -- no device attached: {}",
                    e.detail_string()
                );
                None
            }
            Err(e) => panic!(
                "a Ledger is attached but unusable, so this is a real failure \
                 rather than a skip: {}",
                e.detail_string()
            ),
        }
    }

    /// Regression test: connect, drop, reconnect — repeatedly, in one process.
    ///
    /// This is the shape that used to abort the whole test binary with SIGTRAP
    /// inside macOS's HID stack. Dropping a signer returned while its device
    /// actor still owned the `hidapi` handle, so the next `connect` initialised
    /// HID concurrently with that teardown. Every operation passed in isolation,
    /// which is precisely why it read as a flaky test instead of a lifecycle bug.
    ///
    /// It needs no button press, and a crash here fails the run rather than
    /// producing a confusing partial pass.
    #[tokio::test]
    #[cfg(feature = "integration-tests")]
    async fn test_ledger_reconnect_cycle_does_not_crash() {
        let Some(first) = try_connect() else { return };
        let pubkey = first.pubkey();
        drop(first);

        for round in 0..3 {
            let signer = LedgerSigner::connect(None, false, None).unwrap_or_else(|e| {
                panic!(
                    "reconnect {round} failed after a clean drop: {}",
                    e.detail_string()
                )
            });
            assert_eq!(
                signer.pubkey(),
                pubkey,
                "the same device must derive the same key across reconnects"
            );
            drop(signer);
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
        // `sign_message` signs the *envelope*, not the raw bytes, so verify
        // against the envelope the backend built. Note this is deliberately not
        // `solana_offchain_message`'s serialization: that layout is rejected by
        // the device, which is what made this path fail on hardware for months.
        // See `ledger_offchain_envelope`.
        let envelope =
            crate::ledger::ledger_offchain_envelope(&signer.pubkey(), message).expect("envelope");
        assert!(
            signature.verify(&signer.pubkey().to_bytes(), &envelope),
            "signature must verify against the envelope the device signed"
        );
        // Guard against a regression to the previous, rejected layout: the
        // signature must NOT verify against the raw payload.
        assert!(
            !signature.verify(&signer.pubkey().to_bytes(), message),
            "signature covers the envelope, not the raw payload"
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
