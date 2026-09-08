/// Which `solana-remote-wallet` this build resolved, for the ledger backend's
/// enumeration error to report instead of guessing.
///
/// Cargo exposes no environment variable for a dependency's resolved version, so
/// this reads the lockfile that governs the build, walking up from the manifest
/// directory. That works for a workspace build and for a path dependency, and it
/// does **not** work when this crate is itself pulled from crates.io: the
/// consumer's lockfile is nowhere near our manifest. That case reports
/// `unknown`, which is the point -- the error message must be able to say it
/// does not know, rather than assert a version it never checked.
fn resolved_remote_wallet_version() -> String {
    let manifest = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => std::path::PathBuf::from(dir),
        Err(_) => return "unknown".to_string(),
    };

    for dir in manifest.ancestors().take(6) {
        let lock = dir.join("Cargo.lock");
        let Ok(text) = std::fs::read_to_string(&lock) else {
            continue;
        };
        println!("cargo:rerun-if-changed={}", lock.display());

        // Minimal `[[package]]` scan rather than a TOML dependency: the shape
        // is `name = "..."` then `version = "..."` within one block.
        let mut in_target = false;
        for line in text.lines() {
            let line = line.trim();
            if line == "[[package]]" {
                in_target = false;
            } else if line == "name = \"solana-remote-wallet\"" {
                in_target = true;
            } else if in_target {
                if let Some(rest) = line.strip_prefix("version = \"") {
                    if let Some(v) = rest.strip_suffix('"') {
                        return v.to_string();
                    }
                }
            }
        }
        // A lockfile was found and read; it simply does not contain the crate
        // (the `ledger` feature is off). No point walking further up.
        return "not-in-graph".to_string();
    }

    "unknown".to_string()
}

fn main() {
    println!(
        "cargo:rustc-env=SOLANA_REMOTE_WALLET_VERSION={}",
        resolved_remote_wallet_version()
    );

    let target_is_browser_wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32")
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("unknown");
    let js_backend_selected =
        std::env::var("CARGO_CFG_GETRANDOM_BACKEND").as_deref() == Ok("wasm_js");
    if target_is_browser_wasm && !js_backend_selected {
        println!(
            "cargo:warning=solana-keychain: building for wasm32-unknown-unknown without a getrandom 0.3 backend. \
             Set RUSTFLAGS='--cfg getrandom_backend=\"wasm_js\"' in the final binary's build, \
             otherwise getrandom will fail to compile."
        );
    }
}
