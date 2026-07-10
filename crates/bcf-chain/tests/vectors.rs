//! Conformance harness for bcf-chain.
//!
//! The vectors under `specs/test-vectors/bcf-chain-and-log/` (and its `receipts/`
//! and `heads/` subdirs) are the contract. Expected values live only in the
//! vector files — never hardcoded here (per `.cursor/rules/rust-quality.mdc`).

use bcf_chain::{
    detect_head_fork, detect_log_equivocation, find_gaps, verify_chain, verify_checkpoint,
    verify_head, verify_inclusion, verify_log_consistency, verify_receipt, ForkVerdict,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn vectors_dir(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/test-vectors")
        .join(sub)
}

fn read_vectors(sub: &str) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(vectors_dir(sub)).expect("vectors dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue; // skip the receipts/ and heads/ subdirectories
        }
        let json: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        out.push((
            path.file_stem().unwrap().to_string_lossy().to_string(),
            json,
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!out.is_empty(), "no vectors found in {sub}");
    out
}

fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn hex32(v: &Value) -> [u8; 32] {
    hex(v).try_into().expect("32-byte hex")
}

fn hex32_list(v: &Value) -> Vec<[u8; 32]> {
    v.as_array().unwrap().iter().map(hex32).collect()
}

fn hex_list(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(hex).collect()
}

/// Assert an error-or-ok outcome against the vector's `expected` block.
fn check(
    name: &str,
    expected: &Value,
    actual: Result<(), &'static str>,
    failures: &mut Vec<String>,
) {
    match (expected["result"].as_str().unwrap(), actual) {
        ("valid", Ok(())) => {}
        ("valid", Err(code)) => failures.push(format!("{name}: expected valid, got {code}")),
        ("error", Ok(())) => failures.push(format!(
            "{name}: expected {}, got valid",
            expected["error"].as_str().unwrap()
        )),
        ("error", Err(code)) => {
            let want = expected["error"].as_str().unwrap();
            if code != want {
                failures.push(format!("{name}: expected {want}, got {code}"));
            }
        }
        (other, _) => failures.push(format!("{name}: unknown result {other}")),
    }
}

#[test]
fn chain_vectors() {
    let mut failures = Vec::new();
    for (name, json) in read_vectors("bcf-chain-and-log") {
        let inputs = &json["inputs"];
        let envelopes: Vec<Vec<u8>> = inputs["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(hex)
            .collect();
        let chain_id = hex32(&inputs["chain_id"]);
        let domain = inputs["expected_domain"].as_str().unwrap();
        let external_refs: Vec<[u8; 32]> = inputs
            .get("external_refs")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().map(hex32).collect())
            .unwrap_or_default();
        let actual =
            verify_chain(&envelopes, &chain_id, domain, &external_refs).map_err(|e| e.code());
        check(&name, &json["expected"], actual, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "chain failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn receipt_vectors() {
    let mut failures = Vec::new();
    for (name, json) in read_vectors("bcf-chain-and-log/receipts") {
        let inputs = &json["inputs"];
        let bytes = hex(&inputs["receipt"]);
        let domain = inputs["expected_domain"].as_str().unwrap();
        match verify_receipt(&bytes, domain) {
            Ok(r) => {
                let expected = &json["expected"];
                let mut ok = expected["result"] == "valid";
                if let Some(ah) = expected.get("artifact_hash") {
                    ok &= hex::encode(r.artifact_hash) == ah.as_str().unwrap();
                }
                if let Some(ra) = expected.get("received_at") {
                    ok &= r.received_at == ra.as_i64().unwrap() as i128;
                }
                if !ok {
                    failures.push(format!("{name}: valid but fields/expectation mismatch"));
                }
            }
            Err(e) => check(&name, &json["expected"], Err(e.code()), &mut failures),
        }
    }
    assert!(
        failures.is_empty(),
        "receipt failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn head_vectors() {
    let mut failures = Vec::new();
    for (name, json) in read_vectors("bcf-chain-and-log/heads") {
        let inputs = &json["inputs"];
        if inputs.get("head").is_some() {
            // verify_head
            match verify_head(
                &hex(&inputs["head"]),
                inputs["expected_domain"].as_str().unwrap(),
            ) {
                Ok(h) => {
                    let e = &json["expected"];
                    let mut ok = e["result"] == "valid";
                    if let Some(r) = e.get("root") {
                        ok &= hex::encode(h.root) == r.as_str().unwrap();
                    }
                    if let Some(c) = e.get("count") {
                        ok &= h.count == c.as_u64().unwrap();
                    }
                    if let Some(ci) = e.get("chain_id") {
                        ok &= hex::encode(h.chain_id) == ci.as_str().unwrap();
                    }
                    if !ok {
                        failures.push(format!("{name}: head valid but fields mismatch"));
                    }
                }
                Err(e) => check(&name, &json["expected"], Err(e.code()), &mut failures),
            }
        } else if inputs.get("leaf").is_some() {
            // verify_inclusion
            let leaf = hex32(&inputs["leaf"]);
            let proof: Vec<[u8; 32]> = inputs["proof"]
                .as_array()
                .unwrap()
                .iter()
                .map(hex32)
                .collect();
            let leaf_index = inputs["leaf_index"].as_u64().unwrap();
            let tree_size = inputs["tree_size"].as_u64().unwrap();
            let root = hex32(&inputs["root"]);
            let actual =
                verify_inclusion(&leaf, &proof, leaf_index, tree_size, &root).map_err(|e| e.code());
            check(&name, &json["expected"], actual, &mut failures);
        } else if inputs.get("head_a").is_some() {
            // detect_head_fork
            let domain = inputs["expected_domain"].as_str().unwrap();
            let actual = detect_head_fork(
                &hex(&inputs["head_a"]),
                &hex32_list(&inputs["members_a"]),
                &hex(&inputs["head_b"]),
                &hex32_list(&inputs["members_b"]),
                domain,
            );
            let want = json["expected"]["result"].as_str().unwrap();
            match actual {
                Ok(ForkVerdict::Fork) if want == "fork" => {}
                Ok(ForkVerdict::NoFork) if want == "no-fork" => {}
                Err(e) if want == "error" => {
                    let wc = json["expected"]["error"].as_str().unwrap();
                    if e.code() != wc {
                        failures.push(format!("{name}: expected {wc}, got {}", e.code()));
                    }
                }
                other => failures.push(format!("{name}: expected {want}, got {other:?}")),
            }
        } else {
            failures.push(format!("{name}: unrecognized head vector shape"));
        }
    }
    assert!(
        failures.is_empty(),
        "head failures:\n{}",
        failures.join("\n")
    );
}

/// Witnessed-log client (§6.3, rung 3): checkpoints (W1-W4), consistency proofs,
/// head-in-log inclusion, and split-view equivocation. One test dispatching by
/// input shape, since the `log/` directory mixes all four.
#[test]
fn log_vectors() {
    let mut failures = Vec::new();
    for (name, json) in read_vectors("bcf-chain-and-log/log") {
        let inputs = &json["inputs"];
        if inputs.get("checkpoint").is_some() {
            // verify_checkpoint (W1-W4)
            let ckpt = hex(&inputs["checkpoint"]);
            let cosigs = hex_list(&inputs["cosignatures"]);
            let witness_set = hex_list(&inputs["witness_set"]);
            let threshold = inputs["threshold"].as_u64().unwrap() as usize;
            let domain = inputs["expected_domain"].as_str().unwrap();
            match verify_checkpoint(&ckpt, domain, &cosigs, &witness_set, threshold) {
                Ok(c) => {
                    let e = &json["expected"];
                    let mut ok = e["result"] == "valid";
                    if let Some(ts) = e.get("tree_size") {
                        ok &= c.tree_size == ts.as_u64().unwrap();
                    }
                    if let Some(lr) = e.get("log_root") {
                        ok &= hex::encode(c.log_root) == lr.as_str().unwrap();
                    }
                    if !ok {
                        failures.push(format!("{name}: checkpoint valid but fields mismatch"));
                    }
                }
                Err(e) => check(&name, &json["expected"], Err(e.code()), &mut failures),
            }
        } else if inputs.get("old_size").is_some() {
            // verify_log_consistency (§6.3.2)
            let old_size = inputs["old_size"].as_u64().unwrap();
            let old_root = hex32(&inputs["old_root"]);
            let new_size = inputs["new_size"].as_u64().unwrap();
            let new_root = hex32(&inputs["new_root"]);
            let proof = hex32_list(&inputs["proof"]);
            let actual = verify_log_consistency(old_size, &old_root, new_size, &new_root, &proof)
                .map_err(|e| e.code());
            check(&name, &json["expected"], actual, &mut failures);
        } else if inputs.get("checkpoint_a").is_some() {
            // detect_log_equivocation (split-view, L1-L3)
            let proof = hex32_list(&inputs["consistency_proof"]);
            let witness_set = hex_list(&inputs["witness_set"]);
            let threshold = inputs["threshold"].as_u64().unwrap() as usize;
            let actual = detect_log_equivocation(
                &hex(&inputs["checkpoint_a"]),
                &hex_list(&inputs["cosignatures_a"]),
                &hex(&inputs["checkpoint_b"]),
                &hex_list(&inputs["cosignatures_b"]),
                &proof,
                inputs["expected_domain"].as_str().unwrap(),
                &witness_set,
                threshold,
            );
            let want = json["expected"]["result"].as_str().unwrap();
            match actual {
                Ok(ForkVerdict::Fork) if want == "fork" => {}
                Ok(ForkVerdict::NoFork) if want == "no-fork" => {}
                Err(e) if want == "error" => {
                    let wc = json["expected"]["error"].as_str().unwrap();
                    if e.code() != wc {
                        failures.push(format!("{name}: expected {wc}, got {}", e.code()));
                    }
                }
                other => failures.push(format!("{name}: expected {want}, got {other:?}")),
            }
        } else if inputs.get("leaf").is_some() {
            // head-in-log inclusion reuses verify_inclusion (P1-P3); leaf is the
            // head hash SHA-256(head_bytes), folded as SHA-256(0x00 || leaf).
            let leaf = hex32(&inputs["leaf"]);
            let proof = hex32_list(&inputs["proof"]);
            let leaf_index = inputs["leaf_index"].as_u64().unwrap();
            let tree_size = inputs["tree_size"].as_u64().unwrap();
            let root = hex32(&inputs["root"]);
            let actual =
                verify_inclusion(&leaf, &proof, leaf_index, tree_size, &root).map_err(|e| e.code());
            check(&name, &json["expected"], actual, &mut failures);
        } else {
            failures.push(format!("{name}: unrecognized log vector shape"));
        }
    }
    assert!(
        failures.is_empty(),
        "log failures:\n{}",
        failures.join("\n")
    );
}

/// Gap-detection over real vector envelopes (no dedicated vectors; §6.1 utility).
#[test]
fn gap_detection() {
    let load = |name: &str| -> Vec<Vec<u8>> {
        let v = read_vectors("bcf-chain-and-log")
            .into_iter()
            .find(|(n, _)| n == name)
            .expect("vector present")
            .1;
        v["inputs"]["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(hex)
            .collect()
    };

    // A complete linear chain holds all its predecessors: no gaps.
    let complete = load("positive-linear-chain");
    assert!(find_gaps(&complete, "BCF/1", &[]).unwrap().is_empty());

    // The gap vector holds a successor whose prev references a withheld hash.
    let with_gap = load("negative-gap");
    let gaps = find_gaps(&with_gap, "BCF/1", &[]).unwrap();
    assert_eq!(gaps.len(), 1, "expected exactly one withheld predecessor");

    // Accepting that hash as an external reference closes the gap.
    let closed = find_gaps(&with_gap, "BCF/1", &gaps).unwrap();
    assert!(closed.is_empty());
}

/// R-C Break 1 regression: a hostile `tree_size` near u64::MAX must terminate
/// with a clean error, never spin (the old loop-based split shifted to zero and
/// hung). Bounded by a generous timeout via a worker thread.
#[test]
fn inclusion_huge_tree_size_terminates() {
    use std::sync::mpsc;
    use std::time::Duration;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let leaf = [0x22u8; 32];
        let root = [0u8; 32];
        for ts in [u64::MAX, (1u64 << 63) + 1, (1u64 << 63) + 99] {
            let r = bcf_chain::verify_inclusion(&leaf, &[], 0, ts, &root);
            assert!(r.is_err()); // empty proof can't match a deep tree
        }
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("verify_inclusion must terminate on hostile tree_size");
}
