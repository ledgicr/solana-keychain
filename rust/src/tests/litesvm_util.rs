use crate::sdk_adapter::{Hash, Pubkey, Transaction};
use std::error::Error;

#[cfg(feature = "sdk-v2")]
use litesvm::LiteSVM;
#[cfg(feature = "sdk-v3")]
use litesvm_v3::LiteSVM;
#[cfg(feature = "sdk-v4")]
use litesvm_v4::LiteSVM;

// Each pinned litesvm exposes simulate_transaction in terms of the same
// solana-transaction major as its paired solana-sdk, so the adapter's own
// Transaction type is the right one to hand it for every SDK version. (litesvm
// 0.13 and earlier were a major behind on sdk-v4 and needed a round-trip
// through a separately-pinned 3.x type; 0.16 moved to solana-transaction 4.x,
// which removed the mismatch.) The bincode hop below is kept as the version
// boundary: it re-decodes the transaction with litesvm's own crate graph.
use crate::sdk_adapter::Transaction as LiteSvmTransaction;

pub async fn start_litesvm(payer: &Pubkey) -> Result<LiteSVM, Box<dyn Error>> {
    let mut svm = LiteSVM::new()
        .with_sysvars()
        .with_default_programs()
        .with_sigverify(true);

    svm.airdrop(payer, 1_000_000_000).unwrap();

    Ok(svm)
}

pub async fn get_latest_blockhash(litesvm: &LiteSVM) -> Result<Hash, Box<dyn Error>> {
    Ok(litesvm.latest_blockhash())
}

pub async fn simulate_transaction(
    litesvm: &LiteSVM,
    transaction: &Transaction,
) -> Result<(), Box<dyn Error>> {
    let tx_bytes = bincode::serialize(transaction).expect("Failed to serialize transaction");

    let tx_for_litesvm: LiteSvmTransaction =
        bincode::deserialize(&tx_bytes).expect("Failed to deserialize transaction");

    let result = litesvm.simulate_transaction(tx_for_litesvm);

    assert!(result.is_ok(), "Failed to simulate transaction");

    Ok(())
}
