#!/usr/bin/env python3
"""Vector generator for bcf-core.md and the chain sections of bcf-chain-and-log.md.

Independent oracle: cbor2 + PyCA cryptography, deliberately NOT the Rust
reference implementation, so the vectors cross-check it (bcf-core.md §12).

All randomness is fixed (seeds, nonces, iat values) so regeneration is
byte-identical. Run from the repo root:

    python3 specs/test-vectors/tools/generate_bcf_core.py
"""

import hashlib
import json
import pathlib

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigdecode_string, sigencode_string

OUT_CORE = pathlib.Path("specs/test-vectors/bcf-core")
OUT_CHAIN = pathlib.Path("specs/test-vectors/bcf-chain-and-log")
OUT_RECEIPTS = pathlib.Path("specs/test-vectors/bcf-chain-and-log/receipts")
OUT_HEADS = pathlib.Path("specs/test-vectors/bcf-chain-and-log/heads")
OUT_LOG = pathlib.Path("specs/test-vectors/bcf-chain-and-log/log")

DOMAIN = "BCF/1"
CONTENT_TYPE = "application/bcf-claim+cbor"
ALG_EDDSA = -8
ALG_ES256K = -47
SECP256K1_N = SECP256k1.order

# --- fixed test material (never real keys) ---------------------------------

# Ed25519 parties (raw 32-byte seeds).
PARTY_SEEDS = {
    "A": bytes.fromhex("0a" * 32),
    "B": bytes.fromhex("0b" * 32),
    "C": bytes.fromhex("0c" * 32),
    "D": bytes.fromhex("0d" * 32),
}
# secp256k1 parties (private scalars). Signed with RFC 6979 deterministic ECDSA
# via the pure-Python `ecdsa` package — an independent oracle from the Rust
# `k256` impl these vectors cross-check.
EC_SCALARS = {
    "P": int.from_bytes(b"\x11" * 32, "big"),
    "Q": int.from_bytes(b"\x22" * 32, "big"),
}
PARTY_IDS = {
    "A": "did:web:psp-a.example",
    "B": "did:web:psp-b.example",
    "C": "did:web:kyc-issuer.example",
    "D": "did:web:subject.example",
    "P": "did:web:rail-p.example",
    "Q": "did:web:rail-q.example",
}
KEYS = {n: Ed25519PrivateKey.from_private_bytes(s) for n, s in PARTY_SEEDS.items()}
EC_KEYS = {n: SigningKey.from_secret_exponent(s, curve=SECP256k1) for n, s in EC_SCALARS.items()}
PUBS = {n: k.public_key().public_bytes_raw() for n, k in KEYS.items()}
EC_PUBS = {n: k.get_verifying_key().to_string("compressed") for n, k in EC_KEYS.items()}
IAT_BASE = 1765432100


def alg_of(name: str) -> int:
    return ALG_ES256K if name in EC_KEYS else ALG_EDDSA


def pub_of(name: str) -> bytes:
    return EC_PUBS[name] if name in EC_KEYS else PUBS[name]


def ec_sign_raw(name: str, message: bytes, high_s: bool = False) -> bytes:
    """Deterministic (RFC 6979) ECDSA over secp256k1, normalised to low-s.
    With high_s=True, emit the malleable n-s form for the negative vector."""
    raw = EC_KEYS[name].sign_deterministic(
        message, hashfunc=hashlib.sha256, sigencode=sigencode_string
    )
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s  # normalise to low-s
    if high_s:
        s = SECP256K1_N - s  # force the malleable high-s form
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    # self-check: both low-s and high-s are valid ECDSA signatures
    EC_KEYS[name].get_verifying_key().verify(
        sig, message, hashfunc=hashlib.sha256, sigdecode=sigdecode_string
    )
    return sig


def nonce(label: str) -> bytes:
    """Deterministic 16-byte 'random' nonce per vector label."""
    return hashlib.sha256(b"bcf-test-nonce:" + label.encode()).digest()[:16]


# --- spec primitives (bcf-core.md sections 2-5) -----------------------------

def _assert_small_keys(obj):
    """Guard: cbor2 canonical ordering (RFC 7049 length-first) coincides with
    RFC 8949 section 4.2.1 bytewise ordering ONLY while every map key is an
    int < 24 (single-byte encoding). Fail loudly the day that stops holding."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            assert isinstance(k, int) and 0 <= k < 24, f"map key {k!r} breaks ordering assumption"
            _assert_small_keys(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _assert_small_keys(v)
    elif isinstance(obj, cbor2.CBORTag):
        _assert_small_keys(obj.value)


def det(obj) -> bytes:
    _assert_small_keys(obj)
    return cbor2.dumps(obj, canonical=True)


def det_lax(obj) -> bytes:
    """For deliberately rule-breaking vectors only: canonical cbor2 encoding
    without the small-key guard. Use only where the vector's purpose is the
    violation itself and key ordering is unambiguous (e.g. single-entry maps)."""
    return cbor2.dumps(obj, canonical=True)


def party_entry(name: str) -> dict:
    return {1: PARTY_IDS[name], 2: pub_of(name), 3: alg_of(name)}


def make_claim(claim_type, label, payload, parties, prev, predicate=None):
    claim = {
        1: DOMAIN,
        2: claim_type,
        3: nonce(label),
        4: hashlib.sha256(payload).digest(),
        5: sorted((party_entry(p) for p in parties), key=det),
        6: prev,
    }
    if predicate is not None:
        claim[7] = predicate
    return claim


def sig_protected(name: str, iat: int) -> bytes:
    kid = hashlib.sha256(pub_of(name)).digest()
    return det({1: alg_of(name), 4: kid, 15: {6: iat}})


BODY_PROTECTED = det({3: CONTENT_TYPE})


def sign(
    name: str,
    claim_bytes: bytes,
    iat: int,
    protected: bytes | None = None,
    high_s: bool = False,
) -> list:
    protected = protected if protected is not None else sig_protected(name, iat)
    sig_structure = det(["Signature", BODY_PROTECTED, protected, b"", claim_bytes])
    if name in EC_KEYS:
        signature = ec_sign_raw(name, sig_structure, high_s=high_s)
    else:
        signature = KEYS[name].sign(sig_structure)
        KEYS[name].public_key().verify(signature, sig_structure)  # self-check
    return [protected, {}, signature]


def envelope(claim, signer_names, claim_bytes=None) -> bytes:
    claim_bytes = claim_bytes if claim_bytes is not None else det(claim)
    sigs = [sign(n, claim_bytes, IAT_BASE + i) for i, n in enumerate(signer_names)]
    return det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, claim_bytes, sigs]))


def claim_hash(claim) -> bytes:
    return hashlib.sha256(det(claim)).digest()


# --- COSE_Sign1 (single signer; receipts and heads) -------------------------

def sign1(name: str, body_bytes: bytes, protected: bytes | None = None,
          high_s: bool = False) -> bytes:
    """A tagged COSE_Sign1 (tag 18) over body_bytes, signed by one party.
    Sig_structure context is 'Signature1' with no per-signer protected field."""
    kid = hashlib.sha256(pub_of(name)).digest()
    protected = protected if protected is not None else det({1: alg_of(name), 4: kid})
    sig_structure = det(["Signature1", protected, b"", body_bytes])
    if name in EC_KEYS:
        signature = ec_sign_raw(name, sig_structure, high_s=high_s)
    else:
        signature = KEYS[name].sign(sig_structure)
        KEYS[name].public_key().verify(signature, sig_structure)
    return det(cbor2.CBORTag(18, [protected, {}, body_bytes, signature]))


def receipt_body(recipient: str, artifact_hash: bytes, received_at: int) -> bytes:
    return det({1: "BCF-RECEIPT/1", 2: artifact_hash, 3: party_entry(recipient),
                4: received_at})


def head_body(publisher: str, chain_id: bytes, root: bytes, count: int,
              published_at: int) -> bytes:
    return det({1: "BCF-HEAD/1", 2: chain_id, 3: root, 4: count, 5: published_at,
                6: party_entry(publisher)})


def checkpoint_body(publisher: str, chain_id: bytes, tree_size: int, log_root: bytes,
                    published_at: int) -> bytes:
    return det({1: "BCF-CKPT/1", 2: chain_id, 3: tree_size, 4: log_root,
                5: published_at, 6: party_entry(publisher)})


def cosig_body(witness: str, checkpoint_hash: bytes, observed_at: int) -> bytes:
    return det({1: "BCF-COSIG/1", 2: checkpoint_hash, 3: party_entry(witness),
                4: observed_at})


# --- RFC 6962 Merkle tree over a sorted, deduplicated leaf set --------------

def _lpo2(n: int) -> int:
    """Largest power of two strictly less than n (RFC 6962 split point)."""
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def merkle_root(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = _lpo2(n)
    return hashlib.sha256(b"\x01" + merkle_root(leaves[:k]) + merkle_root(leaves[k:])).digest()


def audit_path(m: int, leaves: list[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.1 audit path for the leaf at index m."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _lpo2(n)
    if m < k:
        return audit_path(m, leaves[:k]) + [merkle_root(leaves[k:])]
    return audit_path(m - k, leaves[k:]) + [merkle_root(leaves[:k])]


def sorted_leaves(claim_hashes: list[bytes]) -> list[bytes]:
    """Deduplicated, bytewise-ascending member set — the head's leaf order."""
    return sorted(set(claim_hashes))


def consistency_proof(m: int, leaves: list[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.2 consistency proof that the size-m log is a prefix of the
    size-n (=len(leaves)) log. Defined for 0 < m < n; m==n or m==0 -> empty."""
    n = len(leaves)
    if m == 0 or m == n:
        return []
    return _subproof(m, leaves, True)


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [merkle_root(leaves)]
    k = _lpo2(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


# --- vector writing ----------------------------------------------------------

def write(outdir, name, description, inputs, expected, attack=None):
    vec = {"description": description, "inputs": inputs, "expected": expected}
    if attack:
        vec["attack"] = attack
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / f"{name}.json").write_text(json.dumps(vec, indent=2) + "\n")


def verify_inputs(env: bytes, payload: bytes | None = None) -> dict:
    inputs = {"envelope": env.hex(), "expected_domain": DOMAIN}
    if payload is not None:
        inputs["payload"] = payload.hex()
    return inputs


# --- bcf-core positive vectors ----------------------------------------------

def gen_core():
    payload = b'{"example":"opaque application payload bytes"}'

    c1 = make_claim("bcf:terms/1", "p1", payload, ["A", "B"], [])
    e1 = envelope(c1, ["A", "B"])
    write(OUT_CORE, "positive-2party-genesis-with-payload",
          "Minimal 2-party Ed25519 genesis claim, payload supplied (V1-V9 all run).",
          verify_inputs(e1, payload),
          {"result": "valid", "claim_hash": claim_hash(c1).hex()})

    write(OUT_CORE, "positive-2party-envelope-only",
          "Same artifact verified without the payload argument (V9 skipped; spec 2.1).",
          verify_inputs(e1),
          {"result": "valid", "claim_hash": claim_hash(c1).hex()})

    c2 = make_claim("bcf:terms/1", "p2", payload, ["A", "B", "C"], [])
    write(OUT_CORE, "positive-3party",
          "Three-party claim: N>2 signers supported natively (forward-guard for multilateral work).",
          verify_inputs(envelope(c2, ["A", "B", "C"]), payload),
          {"result": "valid", "claim_hash": claim_hash(c2).hex()})

    c3 = make_claim("bcf:attest/1", "p3", payload, ["A", "B"],
                    [claim_hash(c1)],
                    predicate=["src:1220" + "ab" * 32, "oci:registry.example/pred@sha256:" + "cd" * 32])
    write(OUT_CORE, "positive-successor-with-predicate-set",
          "Successor claim (prev = [genesis]) carrying a two-entry predicate_id_set (spec 9).",
          verify_inputs(envelope(c3, ["A", "B"])),
          {"result": "valid", "claim_hash": claim_hash(c3).hex()})

    # -- ES256K (secp256k1), independent oracle: pure-Python `ecdsa` --
    c_ec = make_claim("bcf:terms/1", "p-es256k", payload, ["P", "Q"], [])
    write(OUT_CORE, "positive-2party-es256k",
          "Two-party ES256K (secp256k1) genesis with low-s deterministic signatures.",
          verify_inputs(envelope(c_ec, ["P", "Q"]), payload),
          {"result": "valid", "claim_hash": claim_hash(c_ec).hex()})

    c_mix = make_claim("bcf:terms/1", "p-mixed", payload, ["A", "P"], [])
    write(OUT_CORE, "positive-mixed-curve",
          "Mixed-curve claim: one Ed25519 signer (A) and one ES256K signer (P).",
          verify_inputs(envelope(c_mix, ["A", "P"]), payload),
          {"result": "valid", "claim_hash": claim_hash(c_mix).hex()})

    gen_core_negative(payload, c1, e1)
    return c1, e1, payload


# --- bcf-core negative vectors (one per removal-table row) -------------------

def gen_core_negative(payload, c1, e1):
    def neg(name, description, env, error, attack, payload_arg=None):
        write(OUT_CORE, name, description, verify_inputs(env, payload_arg),
              {"result": "error", "error": error}, attack)

    bad = make_claim("bcf:terms/1", "n-domain", payload, ["A", "B"], [])
    bad[1] = "XYZ/1"
    neg("negative-wrong-domain", "Claim domain is 'XYZ/1', caller expects 'BCF/1' (V4).",
        envelope(bad, ["A", "B"]), "E_DOMAIN",
        "Cross-protocol confusion: signatures collected under another domain replayed as BCF commitments.")

    bad = make_claim("bcf:terms/1", "n-ctype", payload, ["A", "B"], [])
    del bad[2]
    neg("negative-claim-type-missing", "Claim lacks key 2 (claim_type) (V3).",
        envelope(bad, ["A", "B"]), "E_STRUCTURE",
        "Type confusion: a verifier cannot tell agreement-about-what; an Attest-shaped claim passes where Terms is expected.")

    bad = make_claim("bcf:terms/1", "n-nonce", payload, ["A", "B"], [])
    del bad[3]
    neg("negative-nonce-missing", "Claim lacks key 3 (nonce) (V3).",
        envelope(bad, ["A", "B"]), "E_STRUCTURE",
        "Cross-session claim-hash collision: identical terms in two sessions share a hash, cross-contaminating chains and receipts.")

    bad = make_claim("bcf:terms/1", "n-prev", payload, ["A", "B"], [])
    del bad[6]
    neg("negative-prev-missing", "Claim lacks key 6 (prev) (V3).",
        envelope(bad, ["A", "B"]), "E_STRUCTURE",
        "Unsigned chain position: the same artifact replays at a different position (genesis vs successor ambiguity).")

    bad = make_claim("bcf:terms/1", "n-unknown", payload, ["A", "B"], [])
    bad[99] = "smuggled"
    # key 99 trips the small-key guard in det(); its sort position is the same
    # under RFC 7049 and RFC 8949 ordering (two-byte 0x1863 after all 1-byte keys)
    bad_bytes = cbor2.dumps(bad, canonical=True)
    neg("negative-unknown-claim-key", "Claim carries unknown key 99 (V3).",
        envelope(bad, ["A", "B"], claim_bytes=bad_bytes), "E_STRUCTURE",
        "Unagreed-field smuggling: content rides inside the signed bytes that implementations silently ignore but other layers may act on.")

    bad = make_claim("bcf:terms/1", "n-uppercase", payload, ["A", "B"], [])
    bad[2] = "bcf:Terms/1"
    neg("negative-claim-type-uppercase", "claim_type contains an uppercase letter, violating the charset rule (V3).",
        envelope(bad, ["A", "B"]), "E_STRUCTURE",
        "Type aliasing: case variants masquerade as distinct claim types, evading every layer that compares types — including chain equivocation detection.")

    bad = make_claim("bcf:terms/1", "n-tee", payload, ["A", "B"], [],
                     predicate=["tee:" + "00" * 16])
    neg("negative-predicate-tee-scheme", "predicate entry uses the tee: scheme, which V3 rejects (spec 2, 9).",
        envelope(bad, ["A", "B"]), "E_STRUCTURE",
        "Scheme smuggling: a TEE measurement (where code ran) is laundered into algorithm identity (what the algorithm is).")

    bad = make_claim("bcf:terms/1", "n-emptypred", payload, ["A", "B"], [], predicate=[])
    neg("negative-predicate-empty", "predicate present but empty (V3).",
        envelope(bad, ["A", "B"]), "E_STRUCTURE",
        "Vacuous equivalence: an empty set asserts the equivalence of nothing while the claim appears predicate-bound.")

    bad = make_claim("bcf:terms/1", "n-partykey", payload, ["A", "B"], [])
    bad[5] = sorted(([{**party_entry("A"), 9: "smuggled"}, party_entry("B")]), key=det)
    neg("negative-party-entry-unknown-key", "A's party entry carries unknown key 9 (V5).",
        envelope(bad, ["A", "B"]), "E_PARTY",
        "Unagreed-field smuggling inside a party entry: signed-but-ignored content rides in the party map (same rule as the claim map).")

    bad = make_claim("bcf:terms/1", "n-unsorted", payload, ["A", "B"], [])
    bad[5] = sorted((party_entry(p) for p in ["A", "B"]), key=det, reverse=True)
    assert cbor2.loads(cbor2.dumps(bad, canonical=True)) == bad  # still canonical CBOR:
    neg("negative-parties-unsorted", "parties array reverse-sorted; bytes remain canonical CBOR, so only V5 can catch it.",
        envelope(bad, ["A", "B"], claim_bytes=cbor2.dumps(bad, canonical=True)), "E_PARTY",
        "Hash splitting of equal claims: party order changes claim_hash, forking dedup, receipts, and equivocation comparison; canonical CBOR never reorders arrays, so the sort rule is the sole guard.")

    neg("negative-payload-hash-mismatch",
        "Valid artifact, but the supplied payload is not the committed one (V9).",
        e1, "E_PAYLOAD_HASH",
        "Payload substitution: parties 'agree' while each holds a different document.",
        payload_arg=b"a different document entirely")

    bad = make_claim("bcf:terms/1", "n-1party", payload, ["A", "B"], [])
    bad[5] = [party_entry("A")]
    neg("negative-single-party", "parties has one entry; claim signed only by A (V5).",
        envelope(bad, ["A"]), "E_PARTY",
        "A unilateral statement masquerades as a bilateral commitment.")

    c = make_claim("bcf:terms/1", "n-dupsig", payload, ["A", "B"], [])
    cb = det(c)
    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb,
                                 [sign("A", cb, IAT_BASE), sign("A", cb, IAT_BASE + 1)]]))
    neg("negative-duplicate-signer", "Two signatures, both by A; B never signed (V6, extras before coverage).",
        env, "E_SIG_EXTRA",
        "One party signs twice to simulate a counterparty.")

    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb, [sign("A", cb, IAT_BASE)]]))
    neg("negative-signature-missing", "Only A signed a 2-party claim (V6).",
        env, "E_SIG_MISSING",
        "A half-signed envelope presented as a bilateral commitment; the missing party never agreed.")

    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb,
                                 [sign("A", cb, IAT_BASE), sign("C", cb, IAT_BASE + 1)]]))
    neg("negative-signer-not-party", "Signature by C, who is not in parties (V6).",
        env, "E_SIG_EXTRA",
        "Signer-set substitution: a relay re-wraps the claim with a different signature set than the parties the claim names.")

    # kid claims B but the signature was produced by A's key
    forged = sign("A", cb, IAT_BASE + 1, protected=sig_protected("B", IAT_BASE + 1))
    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb, [sign("A", cb, IAT_BASE), forged]]))
    neg("negative-kid-signature-mismatch", "kid binds to B but the signature bytes are A's (V8).",
        env, "E_SIG_INVALID",
        "Signature/party mix-and-match: a valid signature attributed to the wrong listed party.")

    wrong_alg = det({1: -7, 4: hashlib.sha256(PUBS["B"]).digest(), 15: {6: IAT_BASE + 1}})
    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb,
                                 [sign("A", cb, IAT_BASE), sign("B", cb, IAT_BASE + 1, protected=wrong_alg)]]))
    neg("negative-alg-confusion", "B's header says ES256 (-7); B's party entry says EdDSA (V7).",
        env, "E_ALG",
        "Algorithm confusion: verification is steered to a different or weaker scheme than the parties agreed in the claim.")

    no_iat = det({1: ALG_EDDSA, 4: hashlib.sha256(PUBS["B"]).digest()})
    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb,
                                 [sign("A", cb, IAT_BASE), sign("B", cb, IAT_BASE + 1, protected=no_iat)]]))
    neg("negative-iat-missing", "B's protected header lacks CWT-claims iat (V7).",
        env, "E_HEADER",
        "No attributable signing time: a party can later claim any signing moment with nothing in evidence.")

    # protected header with keys in insertion order 4,1,15 -- valid signature
    # over those exact bytes, but the inner .cbor item is not deterministic
    kid_b = hashlib.sha256(PUBS["B"]).digest()
    nc_prot = cbor2.dumps({4: kid_b, 1: ALG_EDDSA, 15: {6: IAT_BASE + 1}})
    assert nc_prot != det({1: ALG_EDDSA, 4: kid_b, 15: {6: IAT_BASE + 1}})
    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb,
                                 [sign("A", cb, IAT_BASE), sign("B", cb, IAT_BASE + 1, protected=nc_prot)]]))
    neg("negative-noncanonical-protected-header",
        "B's protected header bstr is CBOR with unsorted keys; the signature over those bytes is valid (V1, recursive canonicality).",
        env, "E_NONCANONICAL",
        "Encoding malleability inside bstr-embedded CBOR: the outer-envelope check alone misses it, yielding byte-distinct envelopes for one logical header.")

    sig_a = sign("A", cb, IAT_BASE)
    sig_b = sign("B", cb, IAT_BASE + 1)
    sig_b_tampered = [sig_b[0], {"x": 1}, sig_b[2]]
    env = det_lax(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb, [sig_a, sig_b_tampered]]))
    neg("negative-unprotected-header-nonempty", "B's signature carries unprotected header content (V7).",
        env, "E_HEADER",
        "Unsigned bytes in the envelope: a relay-writable, signature-free field for injecting or altering content in transit.")

    env = det_lax(cbor2.CBORTag(98, [BODY_PROTECTED, {"x": 1}, cb, [sig_a, sig_b]]))
    neg("negative-body-unprotected-nonempty", "Body unprotected map is non-empty (V2).",
        env, "E_ENVELOPE",
        "Unsigned bytes in the envelope at the body level (same attack as per-signature unprotected content).")

    env = det(cbor2.CBORTag(98, [det({3: "application/cose; cose-type=cose-sign"}), {}, cb, [sig_a, sig_b]]))
    neg("negative-wrong-content-type", "Body protected content type is not application/bcf-claim+cbor (V2).",
        env, "E_ENVELOPE",
        "Format confusion: a non-BCF COSE_Sign message is presented to a BCF verifier (and vice versa at sloppier decoders).")

    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, None,
                                 [sign("A", det(c1), IAT_BASE), sign("B", det(c1), IAT_BASE + 1)]]))
    neg("negative-detached-payload", "Payload is nil (detached) (V2).",
        env, "E_ENVELOPE",
        "Verification against an absent claim: claim bytes fetched out-of-band may belong to a different agreement.")

    neg("negative-untagged", "Envelope lacks CBOR tag 98 (V1).",
        e1[2:],  # strip the d8 62 tag prefix
        "E_DECODE",
        "Format confusion with other COSE message types at decoders that dispatch on the tag.")

    flipped = bytearray(e1)
    flipped[-1] ^= 0x01  # last byte of the final signature
    neg("negative-signature-invalid", "Final signature has one bit flipped (V8).",
        bytes(flipped), "E_SIG_INVALID",
        "Plain forgery: tampered or fabricated signature bytes.")

    # non-canonical claim: same content, keys encoded in insertion order 2,1,...
    shuffled = {2: c1[2], 1: c1[1], 3: c1[3], 4: c1[4], 5: c1[5], 6: c1[6]}
    nc_claim = cbor2.dumps(shuffled)  # NOT canonical: preserves insertion order
    assert nc_claim != det(c1) and cbor2.loads(nc_claim) == cbor2.loads(det(c1))
    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, nc_claim,
                                 [sign("A", nc_claim, IAT_BASE), sign("B", nc_claim, IAT_BASE + 1)]]))
    neg("negative-noncanonical-claim", "Claim map keys in non-sorted order; signatures are otherwise valid over those bytes (V3).",
        env, "E_NONCANONICAL",
        "Encoding malleability: semantically identical claims with different bytes yield different claim_hashes, silently forking chains and receipts.")

    # non-canonical envelope: outer 4-element array re-encoded indefinite-length
    body = e1[2:]  # after d8 62 tag
    assert body[0] == 0x84
    env = e1[:2] + b"\x9f" + body[1:] + b"\xff"
    neg("negative-noncanonical-envelope", "Outer COSE_Sign array uses indefinite-length encoding (V1).",
        env, "E_NONCANONICAL",
        "Encoding malleability at the envelope layer (same attack class as the claim-level variant).")

    # ES256K high-s: a valid ECDSA signature in the malleable n-s form (V8).
    c_hs = make_claim("bcf:terms/1", "n-highs", payload, ["P", "Q"], [])
    cb_hs = det(c_hs)
    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb_hs,
                                 [sign("P", cb_hs, IAT_BASE),
                                  sign("Q", cb_hs, IAT_BASE + 1, high_s=True)]]))
    neg("negative-es256k-high-s",
        "Q's ES256K signature is the high-s (malleable) form; valid ECDSA but rejected (V8, low-s rule).",
        env, "E_SIG_INVALID",
        "Signature malleability: anyone holding the artifact mints a second byte-distinct valid signature for the same claim.")

    # ES256K alg/pub-length mismatch: alg says secp256k1 (-47), key is 32 bytes (V5).
    bad = make_claim("bcf:terms/1", "n-ec-publen", payload, ["P", "Q"], [])
    for entry in bad[5]:
        if entry[3] == ALG_ES256K and entry[2] == EC_PUBS["P"]:
            entry[2] = EC_PUBS["P"][:32]  # 33-byte compressed key truncated to 32
    cb_bad = det(bad)
    env = det(cbor2.CBORTag(98, [BODY_PROTECTED, {}, cb_bad,
                                 [sign("P", cb_bad, IAT_BASE), sign("Q", cb_bad, IAT_BASE + 1)]]))
    neg("negative-es256k-alg-pub-mismatch",
        "A party declares alg -47 (secp256k1) but carries a 32-byte key (V5).",
        env, "E_PARTY",
        "Algorithm/key-length confusion: a key is interpreted under an algorithm its length cannot support.")


# --- chain vectors (bcf-chain-and-log.md section 8) --------------------------

def chain_inputs(envs, chain_id, external=()):
    d = {"envelopes": [e.hex() for e in envs], "chain_id": chain_id.hex(),
         "expected_domain": DOMAIN}
    if external:
        d["external_refs"] = [h.hex() for h in external]
    return d


def gen_chain():
    payload = b"chain payload"

    genesis = make_claim("bcf:terms/1", "ch-g", payload, ["A", "B"], [])
    g_hash, g_env = claim_hash(genesis), envelope(genesis, ["A", "B"])

    s1 = make_claim("bcf:step/1", "ch-s1", payload, ["A", "B"], [g_hash])
    s1_hash, s1_env = claim_hash(s1), envelope(s1, ["A", "B"])

    s2 = make_claim("bcf:step/1", "ch-s2", payload, ["A", "B"], [s1_hash])
    write(OUT_CHAIN, "positive-linear-chain",
          "Genesis -> step -> step, same parties throughout (C1-C5).",
          chain_inputs([g_env, s1_env, envelope(s2, ["A", "B"])], g_hash),
          {"result": "valid"})

    kyc = make_claim("bcf:attest/kyc/1", "ch-kyc", b"kyc evidence", ["C", "D"], [])
    kyc_hash, kyc_env = claim_hash(kyc), envelope(kyc, ["C", "D"])
    join = make_claim("bcf:step/1", "ch-join", payload, ["A", "B"], sorted([g_hash, kyc_hash]))
    write(OUT_CHAIN, "positive-mixed-types-and-join",
          "KYC attestation by (C,D) imported by reference into an (A,B) chain via a join claim (spec sections 2 and 4).",
          chain_inputs([g_env, kyc_env, envelope(join, ["A", "B"])], g_hash),
          {"result": "valid"})

    other = make_claim("bcf:receipt/1", "ch-difftype", b"receipt", ["A", "B"], [g_hash])
    write(OUT_CHAIN, "negative-equivocation-different-types",
          "Two successors of genesis with DIFFERENT claim_types, both signed by the same parties: branching is equivocation regardless of type (spec section 5 strict rule).",
          chain_inputs([g_env, s1_env, envelope(other, ["A", "B"])], g_hash),
          {"result": "error", "error": "E_EQUIVOCATION"},
          attack="Type-rename evasion: a cheater forks the session under a fresh claim_type; a type-keyed equivocation rule would call it legitimate.")

    bridge = make_claim("bcf:bridge/1", "ch-bridge", b"bridge", ["A", "B"], [g_hash])
    b_hash = claim_hash(bridge)
    rooted = make_claim("bcf:step/1", "ch-reparent", b"conflicting story", ["A", "B"], [b_hash])
    write(OUT_CHAIN, "negative-equivocation-reparent",
          "Cheater interposes a throwaway bridge claim on genesis, then roots the conflicting step on it; the two step claims share no prev entry, but the bridge itself is a second successor of genesis (spec section 5).",
          chain_inputs([g_env, s1_env, envelope(bridge, ["A", "B"]), envelope(rooted, ["A", "B"])], g_hash),
          {"result": "error", "error": "E_EQUIVOCATION"},
          attack="Re-parenting evasion: divergence is hidden one hop away from the fork point; the strict rule catches the bridge as the branching act.")

    stray = make_claim("bcf:terms/1", "ch-stray", b"unrelated", ["C", "D"], [])
    write(OUT_CHAIN, "negative-unrelated-artifact",
          "Input set contains an artifact that is neither a member nor referenced by any member's prev (C2 partition).",
          chain_inputs([g_env, s1_env, envelope(stray, ["C", "D"])], g_hash),
          {"result": "error", "error": "E_CHAIN_UNREACHABLE"},
          attack="Evidence smuggling: an unrelated artifact rides in the input set and acquires the appearance of belonging to the session.")

    write(OUT_CHAIN, "negative-gap",
          "Successor references the genesis and an unknown hash not in the set nor in external_refs (C3).",
          chain_inputs([g_env, envelope(make_claim("bcf:step/1", "ch-gap", payload, ["A", "B"],
                                                   sorted([g_hash, hashlib.sha256(b"missing").digest()])), ["A", "B"])],
                       g_hash),
          {"result": "error", "error": "E_CHAIN_GAP"},
          attack="Withholding made invisible: a presenter omits inconvenient artifacts and the chain still verifies.")

    write(OUT_CHAIN, "negative-wrong-root",
          "chain_id names a hash that is no artifact in the set (C2).",
          chain_inputs([g_env, s1_env], hashlib.sha256(b"not-a-root").digest()),
          {"result": "error", "error": "E_CHAIN_ROOT"},
          attack="Session substitution: artifacts presented as belonging to a session whose genesis they never descend from.")

    dup = make_claim("bcf:step/1", "ch-dup", payload, ["A", "B"], [g_hash, g_hash])
    write(OUT_CHAIN, "negative-duplicate-prev",
          "Successor lists the same prev hash twice (spec section 2).",
          chain_inputs([g_env, envelope(dup, ["A", "B"])], g_hash),
          {"result": "error", "error": "E_CHAIN_STRUCTURE"},
          attack="Reference-count games: layers that count predecessor references (joins, receipts) are inflated without new evidence.")

    eq = make_claim("bcf:step/1", "ch-equiv", b"a different story", ["A", "B"], [g_hash])
    write(OUT_CHAIN, "negative-equivocation",
          "Two distinct bcf:step/1 claims by the same parties extend the same prev entry; both halves individually valid (C4).",
          chain_inputs([g_env, s1_env, envelope(eq, ["A", "B"])], g_hash),
          {"result": "error", "error": "E_EQUIVOCATION"},
          attack="Double-story: a party advances two conflicting session states from one position; the pair of envelopes is the self-contained proof.")

    # Cycles: a genuine prev-cycle requires a hash preimage and cannot be
    # constructed, so no vector exists by design; the spec carries this as an
    # implementation note (bounded traversal), not a priced check.


# --- receipts (spec §6.1) ----------------------------------------------------

def gen_receipts():
    art = bytes.fromhex("aa" * 32)  # an acknowledged artifact's claim_hash
    rcvd = IAT_BASE + 500

    def vec(name, description, receipt, expected, attack=None):
        write(OUT_RECEIPTS, name, description,
              {"receipt": receipt.hex(), "expected_domain": "BCF-RECEIPT/1"},
              expected, attack)

    body = receipt_body("A", art, rcvd)
    vec("positive-ed25519",
        "Valid Ed25519 receipt acknowledging artifact aa..aa (R1-R5).",
        sign1("A", body),
        {"result": "valid", "artifact_hash": art.hex(), "received_at": rcvd})

    body_ec = receipt_body("P", art, rcvd)
    vec("positive-es256k",
        "Valid ES256K receipt, low-s (R1-R5).",
        sign1("P", body_ec),
        {"result": "valid", "artifact_hash": art.hex(), "received_at": rcvd})

    bad = det({1: "XYZ/1", 2: art, 3: party_entry("A"), 4: rcvd})
    vec("negative-wrong-domain", "Receipt domain is not BCF-RECEIPT/1 (R3).",
        sign1("A", bad), {"result": "error", "error": "E_RECEIPT_DOMAIN"},
        "Cross-confusion: a receipt under another domain is replayed as a BCF-RECEIPT acknowledgement.")

    bad = det({1: "BCF-RECEIPT/1", 2: art, 3: party_entry("A"), 4: rcvd, 6: "prev-smuggled"})
    vec("negative-extra-key", "Receipt body carries an unknown key 6 (R2).",
        sign1("A", bad), {"result": "error", "error": "E_RECEIPT_STRUCTURE"},
        "Unagreed-field smuggling: content rides in the signed receipt body that the format does not define (a receipt has no prev).")

    bad = det({1: "BCF-RECEIPT/1", 2: art[:16], 3: party_entry("A"), 4: rcvd})
    vec("negative-short-artifact-hash", "artifact_hash is 16 bytes, not 32 (R2).",
        sign1("A", bad), {"result": "error", "error": "E_RECEIPT_STRUCTURE"},
        "Malformed binding: the receipt acknowledges something other than a 32-byte claim_hash.")

    # kid in the protected header does not match SHA-256(recipient.pub)
    wrong_kid = det({1: ALG_EDDSA, 4: hashlib.sha256(PUBS["B"]).digest()})
    vec("negative-kid-mismatch", "Protected kid is B's, but recipient in the body is A (R4).",
        sign1("A", receipt_body("A", art, rcvd), protected=wrong_kid),
        {"result": "error", "error": "E_RECEIPT_STRUCTURE"},
        "Header/body signer disagreement: the attributing key does not match the body's named recipient.")

    good = sign1("A", receipt_body("A", art, rcvd))
    flipped = bytearray(good)
    flipped[-1] ^= 0x01
    vec("negative-bad-signature", "Final signature byte flipped (R5).",
        bytes(flipped), {"result": "error", "error": "E_RECEIPT_SIG"},
        "Forgery: tampered receipt signature.")


# --- chain heads (spec §6.2) -------------------------------------------------

def gen_heads():
    chain_id = bytes.fromhex("11" * 32)
    pub_at = IAT_BASE + 900
    members = [bytes.fromhex(b * 32) for b in ("22", "33", "44", "55", "66")]
    leaves = sorted_leaves(members)
    root = merkle_root(leaves)

    def head_vec(name, description, head, expected, attack=None):
        write(OUT_HEADS, name, description,
              {"head": head.hex(), "expected_domain": "BCF-HEAD/1"}, expected, attack)

    h = sign1("A", head_body("A", chain_id, root, len(leaves), pub_at))
    head_vec("positive-multi-leaf",
             "Signed head over a 5-leaf sorted member set (golden root).",
             h, {"result": "valid", "chain_id": chain_id.hex(), "root": root.hex(),
                 "count": len(leaves)})

    one = sorted_leaves([members[0]])
    h1 = sign1("A", head_body("A", chain_id, merkle_root(one), 1, pub_at))
    head_vec("positive-single-leaf", "Signed head over a single-leaf set.",
             h1, {"result": "valid", "chain_id": chain_id.hex(),
                  "root": merkle_root(one).hex(), "count": 1})

    empty_root = merkle_root([])
    h0 = sign1("A", head_body("A", chain_id, empty_root, 0, pub_at))
    head_vec("positive-empty", "Signed head over the empty set (root = SHA-256 of empty).",
             h0, {"result": "valid", "chain_id": chain_id.hex(),
                  "root": empty_root.hex(), "count": 0})

    bad = det({1: "XYZ/1", 2: chain_id, 3: root, 4: len(leaves), 5: pub_at,
               6: party_entry("A")})
    head_vec("negative-wrong-domain", "Head domain is not BCF-HEAD/1.",
             sign1("A", bad), {"result": "error", "error": "E_HEAD_DOMAIN"},
             "A head under another domain is mistaken for a chain-membership commitment.")

    flipped = bytearray(h)
    flipped[-1] ^= 0x01
    head_vec("negative-bad-signature", "Final signature byte flipped.",
             bytes(flipped), {"result": "error", "error": "E_HEAD_SIG"},
             "Forgery: an unsigned/altered head is repudiable, so withholding evidence attributes to no one.")

    bad = det({1: "BCF-HEAD/1", 2: chain_id, 3: root, 4: len(leaves), 5: pub_at,
               6: party_entry("A"), 7: "smuggled"})
    head_vec("negative-extra-key", "Head body carries an unknown key 7.",
             sign1("A", bad), {"result": "error", "error": "E_HEAD_STRUCTURE"},
             "Unagreed-field smuggling: signed content the head format does not define.")

    # Inclusion proofs (verify against the golden root above).
    def incl_vec(name, description, leaf, proof, leaf_index, tree_size, root_hex, expected, attack=None):
        write(OUT_HEADS, name, description,
              {"leaf": leaf.hex(), "proof": [p.hex() for p in proof],
               "leaf_index": leaf_index, "tree_size": tree_size, "root": root_hex},
              expected, attack)

    idx = 2
    incl_vec("inclusion-positive",
             f"Valid RFC 6962 audit path for leaf {idx} of {len(leaves)}.",
             leaves[idx], audit_path(idx, leaves), idx, len(leaves), root.hex(),
             {"result": "valid"})

    not_member = bytes.fromhex("77" * 32)
    incl_vec("inclusion-negative-not-member",
             "Inclusion proof presented for a leaf that is not in the committed set.",
             not_member, audit_path(idx, leaves), idx, len(leaves), root.hex(),
             {"result": "error", "error": "E_HEAD_INCLUSION"},
             "Forged membership: claiming an artifact was committed when the root does not cover it.")

    tampered = audit_path(idx, leaves)
    tampered[0] = bytes(b ^ 0x01 for b in tampered[0])
    incl_vec("inclusion-negative-flipped-node",
             "Valid leaf and index, but one audit-path node is corrupted.",
             leaves[idx], tampered, idx, len(leaves), root.hex(),
             {"result": "error", "error": "E_HEAD_INCLUSION"},
             "Second-preimage / path forgery: a corrupted path must not recompute the committed root.")

    incl_vec("inclusion-negative-wrong-index",
             "A path valid for leaf index 2 presented with leaf_index 1 (geometry mismatch).",
             leaves[idx], audit_path(idx, leaves), 1, len(leaves), root.hex(),
             {"result": "error", "error": "E_HEAD_INCLUSION"},
             "Forged geometry: a path verified against the wrong (index,size) folds left/right wrongly and must not reach the committed root.")

    incl_vec("inclusion-positive-single-leaf",
             "Inclusion in a single-leaf tree: empty path, root = leaf hash.",
             one[0], [], 0, 1, merkle_root(one).hex(),
             {"result": "valid"})

    # Head-fork detection given both member sets.
    set_a = sorted_leaves(members[:3])
    set_b_fork = sorted_leaves(members[1:4])  # overlaps but neither is a superset
    set_b_grow = sorted_leaves(members[:4])   # superset of set_a (honest growth)
    head_a = sign1("A", head_body("A", chain_id, merkle_root(set_a), len(set_a), pub_at))
    head_b_fork = sign1("A", head_body("A", chain_id, merkle_root(set_b_fork), len(set_b_fork), pub_at + 1))
    head_b_grow = sign1("A", head_body("A", chain_id, merkle_root(set_b_grow), len(set_b_grow), pub_at + 1))

    def fork_vec(name, description, ha, hb, ma, mb, expected):
        write(OUT_HEADS, name, description,
              {"head_a": ha.hex(), "head_b": hb.hex(),
               "members_a": [m.hex() for m in ma], "members_b": [m.hex() for m in mb],
               "expected_domain": "BCF-HEAD/1"},
              {"result": expected})

    fork_vec("fork-positive",
             "Two heads by one publisher for one chain_id, neither set a superset of the other -> fork.",
             head_a, head_b_fork, set_a, set_b_fork, "fork")
    fork_vec("fork-negative-growth",
             "Later head's set is a superset of the earlier (honest growth) -> not a fork.",
             head_a, head_b_grow, set_a, set_b_grow, "no-fork")

    # F2: different publisher -> not one party's two stories.
    head_b_other = sign1("B", head_body("B", chain_id, merkle_root(set_b_fork), len(set_b_fork), pub_at + 1))
    fork_vec("fork-negative-different-publisher",
             "Two heads for one chain_id but by different publishers (A, B) -> not comparable (no-fork).",
             head_a, head_b_other, set_a, set_b_fork, "no-fork")

    # F3: a presented member list that does not hash to the signed root is rejected
    # before any superset reasoning (frames an honest publisher / hides a real fork).
    def fork_err_vec(name, description, ha, hb, ma, mb, error):
        write(OUT_HEADS, name, description,
              {"head_a": ha.hex(), "head_b": hb.hex(),
               "members_a": [m.hex() for m in ma], "members_b": [m.hex() for m in mb],
               "expected_domain": "BCF-HEAD/1"},
              {"result": "error", "error": error},
              attack="Fabricated member list: presented members do not hash to the signed root, so superset reasoning on them could frame an honest publisher or hide a real fork.")

    fork_err_vec("fork-negative-bad-members",
                 "members_a does not hash to head_a.root (F3 binding fails).",
                 head_a, head_b_grow, sorted_leaves([members[4]]), set_b_grow,
                 "E_HEAD_STRUCTURE")


# --- witnessed log (spec §6.3) ----------------------------------------------

def gen_log():
    """Rung 3: checkpoints, witness co-signatures, consistency proofs, head-in-log
    inclusion, and split-view detection. Witness set = {C, D}, threshold T = 2."""
    chain_id = bytes.fromhex("11" * 32)
    pub_at = IAT_BASE + 2000

    # A 5-epoch head-log: epoch i commits the first (i+1) members; the log leaf is
    # the head hash SHA-256(head_bytes).
    members = [bytes.fromhex(b * 32) for b in ("22", "33", "44", "55", "66")]

    def head_at(epoch: int) -> bytes:
        leaves = sorted_leaves(members[: epoch + 1])
        return sign1("A", head_body("A", chain_id, merkle_root(leaves), len(leaves), pub_at + epoch))

    head_bytes = [head_at(i) for i in range(5)]
    head_hashes = [hashlib.sha256(h).digest() for h in head_bytes]  # log leaf values

    def checkpoint(size: int, pub: str = "A") -> bytes:
        log_root = merkle_root(head_hashes[:size])
        return sign1(pub, checkpoint_body(pub, chain_id, size, log_root, pub_at + 100 + size))

    def cosign(ckpt: bytes, witness: str, observed_at: int = pub_at + 200) -> bytes:
        return sign1(witness, cosig_body(witness, hashlib.sha256(ckpt).digest(), observed_at))

    DEFAULT_WSET = ["C", "D"]

    def ckpt_vec(name, description, ckpt, cosigs, expected, attack=None, wset=None):
        names = wset if wset is not None else DEFAULT_WSET
        write(OUT_LOG, name, description,
              {"checkpoint": ckpt.hex(),
               "cosignatures": [c.hex() for c in cosigs],
               "witness_set": [pub_of(n).hex() for n in names],
               "threshold": 2,
               "expected_domain": "BCF-CKPT/1"},
              expected, attack)

    ck5 = checkpoint(5)
    ck5_hash = hashlib.sha256(ck5).digest()
    ckpt_vec("checkpoint-positive",
             "Witnessed checkpoint at tree_size 5: publisher sig + 2 distinct in-set witness co-sigs (W1-W4).",
             ck5, [cosign(ck5, "C"), cosign(ck5, "D")],
             {"result": "valid", "tree_size": 5,
              "log_root": merkle_root(head_hashes).hex()})

    ckpt_vec("checkpoint-negative-below-threshold",
             "Only 1 co-signature; threshold is 2 (W4).",
             ck5, [cosign(ck5, "C")],
             {"result": "error", "error": "E_CKPT_WITNESS"},
             "One witness rubber-stamps a fork: below-threshold acceptance defeats independent witnessing.")

    ckpt_vec("checkpoint-negative-non-distinct",
             "Two BYTE-DISTINCT co-signatures, both by witness C (differing observed_at); not 2 distinct witnesses by pub (W4).",
             ck5, [cosign(ck5, "C", pub_at + 200), cosign(ck5, "C", pub_at + 201)],
             {"result": "error", "error": "E_CKPT_WITNESS"},
             "Sybil-of-one: one witness emits several distinct co-signatures (e.g. differing observed_at) to manufacture a quorum; distinctness must be keyed by witness.pub.")

    ckpt_vec("checkpoint-negative-out-of-set",
             "Co-signatures by C and B; B is not in the witness set {C, D} (W4).",
             ck5, [cosign(ck5, "C"), cosign(ck5, "B")],
             {"result": "error", "error": "E_CKPT_WITNESS"},
             "Unauthorized witness: a co-signature from outside the trusted set is counted toward threshold.")

    # Publisher A is also placed in the witness set and co-signs; it must not count.
    ckpt_vec("checkpoint-negative-self-witness",
             "witness_set is {A, C}, threshold 2; A is the publisher and co-signs — A must not count, leaving only C (W4).",
             ck5, [cosign(ck5, "A"), cosign(ck5, "C")],
             {"result": "error", "error": "E_CKPT_WITNESS"},
             "Self-witnessing: the publisher counts toward its own independent-witness threshold.",
             wset=["A", "C"])

    # A wrong-domain body (BCF-RECEIPT/1) by an in-set witness must not count as a co-signature.
    wrong_dom_cosig = sign1("C", det({1: "BCF-RECEIPT/1", 2: ck5_hash, 3: party_entry("C"), 4: pub_at + 200}))
    ckpt_vec("checkpoint-negative-cosig-wrong-domain",
             "A BCF-RECEIPT/1 body by witness C (shape-identical to a co-signature) presented as a co-signature; only D's real co-sig counts (W4).",
             ck5, [cosign(ck5, "D"), wrong_dom_cosig],
             {"result": "error", "error": "E_CKPT_WITNESS"},
             "Type confusion: a receipt (\"I received\") is counted as a witness attestation (\"I vouch\"); the co-signature domain/structure must be checked.")

    neg_size = sign1("A", det({1: "BCF-CKPT/1", 2: chain_id, 3: -1, 4: merkle_root(head_hashes),
                               5: pub_at, 6: party_entry("A")}))
    ckpt_vec("checkpoint-negative-tree-size", "Checkpoint tree_size is negative (W1 structure).",
             neg_size, [cosign(neg_size, "C"), cosign(neg_size, "D")],
             {"result": "error", "error": "E_CKPT_STRUCTURE"},
             "Absurd tree size: a negative/oversized tree_size must be rejected before it drives the Merkle recursion.")

    # A co-signature binding a different checkpoint's hash must not count.
    ck3 = checkpoint(3)
    wrong_cosig = cosign(ck3, "D")  # D co-signs the size-3 checkpoint, presented against size-5
    ckpt_vec("checkpoint-negative-wrong-binding",
             "D's co-signature binds the size-3 checkpoint hash, presented against the size-5 checkpoint (W4).",
             ck5, [cosign(ck5, "C"), wrong_cosig],
             {"result": "error", "error": "E_CKPT_WITNESS"},
             "Co-signature transplant: a witness attestation of log A is replayed as attestation of B.")

    bad_dom = sign1("A", det({1: "XYZ/1", 2: chain_id, 3: 5, 4: merkle_root(head_hashes),
                              5: pub_at, 6: party_entry("A")}))
    ckpt_vec("checkpoint-negative-wrong-domain", "Checkpoint domain is not BCF-CKPT/1 (W2).",
             bad_dom, [cosign(bad_dom, "C"), cosign(bad_dom, "D")],
             {"result": "error", "error": "E_CKPT_DOMAIN"},
             "Domain confusion: a non-checkpoint COSE_Sign1 is accepted as a checkpoint.")

    flipped = bytearray(ck5)
    flipped[-1] ^= 0x01
    ckpt_vec("checkpoint-negative-bad-signature", "Publisher signature byte flipped (W3).",
             bytes(flipped), [cosign(ck5, "C"), cosign(ck5, "D")],
             {"result": "error", "error": "E_CKPT_SIG"},
             "Forgery: an unsigned/altered checkpoint is repudiable.")

    # Consistency proofs (RFC 6962 §2.1.2).
    def cons_vec(name, description, old_size, new_size, proof, expected, attack=None):
        write(OUT_LOG, name, description,
              {"old_size": old_size, "old_root": merkle_root(head_hashes[:old_size]).hex(),
               "new_size": new_size, "new_root": merkle_root(head_hashes[:new_size]).hex(),
               "proof": [p.hex() for p in proof]},
              expected, attack)

    cons_vec("consistency-positive", "Size 3 is a prefix of size 5 (valid extension).",
             3, 5, consistency_proof(3, head_hashes[:5]), {"result": "valid"})
    cons_vec("consistency-positive-empty-old", "old_size 0 is trivially a prefix of size 5.",
             0, 5, [], {"result": "valid"})
    cons_vec("consistency-positive-equal", "Equal size, equal root (trivial).",
             5, 5, [], {"result": "valid"})
    cons_vec("consistency-negative-tampered", "A proof node is corrupted.",
             3, 5, [bytes(b ^ 0x01 for b in p) for p in consistency_proof(3, head_hashes[:5])],
             {"result": "error", "error": "E_LOG_CONSISTENCY"},
             "History rewrite: a tampered consistency proof must not bridge an old root to an unrelated new root.")

    write(OUT_LOG, "consistency-negative-non-monotone",
          "old_size 5 > new_size 3 (the log appears to have shrunk).",
          {"old_size": 5, "old_root": merkle_root(head_hashes[:5]).hex(),
           "new_size": 3, "new_root": merkle_root(head_hashes[:3]).hex(),
           "proof": [p.hex() for p in consistency_proof(3, head_hashes[:5])]},
          {"result": "error", "error": "E_LOG_CONSISTENCY"},
          attack="Truncation: a publisher presents a smaller log as a successor, dropping committed heads.")

    other5 = head_hashes[:4] + [hashlib.sha256(b"divergent epoch 4").digest()]
    write(OUT_LOG, "consistency-negative-equal-size-diff-root",
          "Equal size (5, 5) but different roots; the empty proof cannot bridge them (§6.3.2 boundary).",
          {"old_size": 5, "old_root": merkle_root(head_hashes[:5]).hex(),
           "new_size": 5, "new_root": merkle_root(other5).hex(), "proof": []},
          {"result": "error", "error": "E_LOG_CONSISTENCY"},
          attack="Same-epoch divergence: two size-5 logs with different roots are not consistent; this is the signal split-view detection rests on.")

    # Head-in-log inclusion: head H_i is the i-th leaf under the size-5 log_root.
    idx = 2
    write(OUT_LOG, "head-in-log-positive",
          f"Head at epoch {idx} is leaf {idx} of the size-5 head-log.",
          {"leaf": head_hashes[idx].hex(), "proof": [p.hex() for p in audit_path(idx, head_hashes)],
           "leaf_index": idx, "tree_size": 5, "root": merkle_root(head_hashes).hex()},
          {"result": "valid"})
    write(OUT_LOG, "head-in-log-negative-wrong-epoch",
          "A path valid for epoch 2 presented with leaf_index 1.",
          {"leaf": head_hashes[idx].hex(), "proof": [p.hex() for p in audit_path(idx, head_hashes)],
           "leaf_index": 1, "tree_size": 5, "root": merkle_root(head_hashes).hex()},
          {"result": "error", "error": "E_HEAD_INCLUSION"},
          attack="Position forgery: a head claimed at the wrong epoch must not verify.")

    # Split-view detection is interactive: detect_log_equivocation takes a
    # consistency proof for the cross-size case (L1-L3).
    forked_heads = head_hashes[:4] + [hashlib.sha256(b"a different epoch 4 head").digest()]
    ck5_fork = sign1("A", checkpoint_body("A", chain_id, 5, merkle_root(forked_heads), pub_at + 105))

    # A genuinely divergent short log (epoch 2 differs), checkpointed at size 3.
    forked3_hashes = head_hashes[:2] + [hashlib.sha256(b"forked epoch 2 head").digest()]
    ck3_fork = sign1("A", checkpoint_body("A", chain_id, 3, merkle_root(forked3_hashes), pub_at + 103))

    def split_vec(name, description, ca, cosa, cb, cosb, proof, expected):
        write(OUT_LOG, name, description,
              {"checkpoint_a": ca.hex(), "cosignatures_a": [c.hex() for c in cosa],
               "checkpoint_b": cb.hex(), "cosignatures_b": [c.hex() for c in cosb],
               "consistency_proof": [p.hex() for p in proof],
               "witness_set": [pub_of("C").hex(), pub_of("D").hex()], "threshold": 2,
               "expected_domain": "BCF-CKPT/1"},
              {"result": expected})

    split_vec("split-view-fork-same-size",
              "Two witnessed size-5 checkpoints with different log_root -> fork (L2).",
              ck5, [cosign(ck5, "C"), cosign(ck5, "D")],
              ck5_fork, [cosign(ck5_fork, "C"), cosign(ck5_fork, "D")], [], "fork")

    split_vec("split-view-honest-extension",
              "Size-3 and size-5 checkpoints with a valid consistency proof bridging them -> no-fork (honest growth, L3).",
              ck3, [cosign(ck3, "C"), cosign(ck3, "D")],
              ck5, [cosign(ck5, "C"), cosign(ck5, "D")],
              consistency_proof(3, head_hashes[:5]), "no-fork")

    split_vec("split-view-fork-cross-size",
              "A forked size-3 checkpoint and the honest size-5 checkpoint; the honest 3->5 proof does not bridge the forked size-3 root -> fork (L3).",
              ck3_fork, [cosign(ck3_fork, "C"), cosign(ck3_fork, "D")],
              ck5, [cosign(ck5, "C"), cosign(ck5, "D")],
              consistency_proof(3, head_hashes[:5]), "fork")


def main():
    c1, e1, payload = gen_core()
    gen_chain()
    gen_receipts()
    gen_heads()
    gen_log()
    ed_parties = {n: {"alg": ALG_EDDSA, "id": PARTY_IDS[n], "seed": PARTY_SEEDS[n].hex(),
                      "pub": PUBS[n].hex(),
                      "kid": hashlib.sha256(PUBS[n]).digest().hex()}
                  for n in PARTY_SEEDS}
    ec_parties = {n: {"alg": ALG_ES256K, "id": PARTY_IDS[n],
                      "scalar": format(EC_SCALARS[n], "064x"),
                      "pub": EC_PUBS[n].hex(),
                      "kid": hashlib.sha256(EC_PUBS[n]).digest().hex()}
                  for n in EC_SCALARS}
    keys_doc = {
        "comment": ("Fixed test keys. NEVER real keys. Ed25519 parties carry raw "
                    "private seeds; secp256k1 parties carry private scalars. ES256K "
                    "signatures are RFC 6979 deterministic, low-s, via the `ecdsa` package."),
        "parties": {**ed_parties, **ec_parties},
        "iat_base": IAT_BASE,
    }
    (OUT_CORE / "test-keys.json").write_text(json.dumps(keys_doc, indent=2) + "\n")
    n_core = len(list(OUT_CORE.glob("*.json"))) - 1
    n_chain = len(list(OUT_CHAIN.glob("*.json")))
    n_receipts = len(list(OUT_RECEIPTS.glob("*.json")))
    n_heads = len(list(OUT_HEADS.glob("*.json")))
    n_log = len(list(OUT_LOG.glob("*.json")))
    print(f"wrote {n_core} bcf-core, {n_chain} chain, {n_receipts} receipt, {n_heads} head, {n_log} log vectors")


if __name__ == "__main__":
    main()
