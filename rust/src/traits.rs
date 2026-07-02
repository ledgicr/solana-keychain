//! Core trait definitions for Solana signers

use async_trait::async_trait;

use crate::error::SignerError;
use crate::sdk_adapter::{Pubkey, Signature, Transaction};

pub type SignedTransaction = (String, Signature);
#[derive(Debug)]
pub enum SignTransactionResult {
    Complete(SignedTransaction),
    Partial(SignedTransaction),
}

impl SignTransactionResult {
    pub fn into_signed_transaction(self) -> SignedTransaction {
        match self {
            Self::Complete(tx) | Self::Partial(tx) => tx,
        }
    }
}

/// Trait for signing Solana transactions
///
/// All signer implementations must implement this trait to provide
/// a unified interface for transaction signing.
#[async_trait]
pub trait SolanaSigner: Send + Sync {
    /// Get the public key of this signer
    fn pubkey(&self) -> Pubkey;

    /// Sign a Solana transaction
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to sign (will be modified in place)
    ///
    /// # Returns
    ///
    /// The encoded transaction/signature tuple, explicitly marked as complete or partial.
    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> Result<SignTransactionResult, SignerError>;

    /// Sign an arbitrary message
    ///
    /// # Arguments
    ///
    /// * `message` - The message bytes to sign
    ///
    /// # Returns
    ///
    /// The signature produced by signing the message
    async fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;

    /// Sign a pre-serialized transaction *message* (legacy or versioned/v0).
    ///
    /// This is distinct from [`sign_message`](Self::sign_message): it signs the
    /// bytes *as a transaction*, not as an arbitrary/off-chain message. For a
    /// software key the two are identical (both raw-ed25519-sign the bytes), so
    /// the default implementation delegates to `sign_message` and every existing
    /// backend keeps working unchanged. A hardware wallet, however, cannot
    /// raw-sign arbitrary bytes — it must route a transaction through its
    /// transaction-parsing APDU — so hardware backends (e.g. Ledger) override
    /// this method.
    ///
    /// Operating on the serialized message bytes (`Message::serialize()` for
    /// legacy, `VersionedMessage::serialize()` for v0) makes this work for both
    /// `Transaction` and `VersionedTransaction`. The caller inserts the returned
    /// signature at the signer's index in the transaction's signature array.
    ///
    /// # Arguments
    ///
    /// * `message` - The serialized transaction message bytes to sign
    ///
    /// # Returns
    ///
    /// The signature over the serialized transaction message
    async fn sign_transaction_message(
        &self,
        message: &[u8],
    ) -> Result<Signature, SignerError> {
        self.sign_message(message).await
    }

    /// Check if the signer is available and healthy
    ///
    /// # Returns
    ///
    /// `true` if the signer can be used, `false` otherwise
    async fn is_available(&self) -> bool;
}
