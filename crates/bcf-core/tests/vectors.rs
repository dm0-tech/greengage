//! Conformance harness.
//!
//! The vectors under `specs/test-vectors/` are the contract; this crate is
//! conformant iff it reproduces every one. Expected bytes live only in the
//! vector files — never hardcoded here (per `.cursor/rules/rust-quality.mdc`).

use bcf_core::verify_bcf;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn vectors_dir(spec: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/test-vectors")
        .join(spec)
}

fn read_vectors(spec: &str) -> Vec<(String, Value)> {
    let dir = vectors_dir(spec);
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).expect("vectors dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        if name == "test-keys" {
            continue; // key material, not a vector
        }
        let json: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        out.push((name, json));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!out.is_empty(), "no vectors found in {spec}");
    out
}

fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// Compare an actual verification outcome to a vector's `expected` block,
/// returning a human-readable mismatch description on failure.
fn check_outcome(
    name: &str,
    expected: &Value,
    actual: Result<Option<[u8; 32]>, &'static str>,
) -> Result<(), String> {
    let want = &expected["result"];
    match (want.as_str().unwrap(), actual) {
        ("valid", Ok(claim_hash)) => {
            // bcf-core vectors pin claim_hash; chain vectors do not carry one.
            if let Some(expected_hash) = expected.get("claim_hash") {
                let got = claim_hash.map(hex::encode).unwrap_or_default();
                if got != expected_hash.as_str().unwrap() {
                    return Err(format!("{name}: claim_hash {got} != {expected_hash}"));
                }
            }
            Ok(())
        }
        ("valid", Err(code)) => Err(format!("{name}: expected valid, got {code}")),
        ("error", Ok(_)) => Err(format!(
            "{name}: expected {}, got valid",
            expected["error"].as_str().unwrap()
        )),
        ("error", Err(code)) => {
            let want_code = expected["error"].as_str().unwrap();
            if code != want_code {
                return Err(format!("{name}: expected {want_code}, got {code}"));
            }
            Ok(())
        }
        (other, _) => Err(format!("{name}: unknown expected.result {other}")),
    }
}

#[test]
fn bcf_core_vectors() {
    let mut failures = Vec::new();
    for (name, json) in read_vectors("bcf-core") {
        let inputs = &json["inputs"];
        let envelope = hex(&inputs["envelope"]);
        let domain = inputs["expected_domain"].as_str().unwrap();
        let payload = inputs.get("payload").map(hex);

        let actual = verify_bcf(&envelope, domain, payload.as_deref())
            .map(|v| Some(v.claim_hash))
            .map_err(|e| e.code());

        if let Err(msg) = check_outcome(&name, &json["expected"], actual) {
            failures.push(msg);
        }
    }
    assert!(
        failures.is_empty(),
        "bcf-core vector failures:\n{}",
        failures.join("\n")
    );
}
