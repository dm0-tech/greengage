//! Deterministic CBOR (RFC 8949 §4.2.1), scoped to the BCF profile.
//!
//! Why hand-rolled rather than a general CBOR crate: the spec's canonicality
//! guarantee is *re-encode-and-compare* (`specs/bcf-core.md` §3) — decode an
//! item, re-encode it canonically, and reject if the bytes differ. A permissive
//! serde codec silently accepts non-canonical input (unsorted keys, non-shortest
//! integers, indefinite lengths), which is exactly what this layer must reject.
//! Owning the bytes is the point.
//!
//! The supported value space is only what the profile uses: integers, byte and
//! text strings, arrays, maps, `null` (for the detached-payload check), and the
//! one outer tag. Floats are forbidden; indefinite lengths are forbidden.

use crate::error::Error;

/// Maximum CBOR nesting depth. The profile nests only a handful of levels
/// (envelope → array → signatures → entries); a small bound turns hostile
/// deep nesting into a clean `E_DECODE` instead of a stack overflow.
const MAX_DEPTH: usize = 16;

/// A decoded CBOR value, restricted to the BCF profile's value space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0/1. Range covers the profile (small keys, alg ids, `iat`).
    Int(i128),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3 (validated UTF-8).
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5, key order preserved as decoded (so canonicality can be judged).
    Map(Vec<(Value, Value)>),
    /// Major type 7, value 22. Needed so the detached-payload case reaches V2.
    Null,
    /// Major type 6. Only the outer COSE_Sign tag is structurally allowed.
    Tag(u64, Box<Value>),
}

impl Value {
    /// Borrow as a byte string, or `None` if a different type.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
    /// Borrow as text, or `None` if a different type.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }
    /// Copy as an integer, or `None` if a different type.
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    /// Borrow as an array, or `None` if a different type.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    /// Borrow as a map, or `None` if a different type.
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }
}

/// Decode exactly one item from `input`, and reject unless `input` is its
/// deterministic encoding. Trailing bytes are `E_DECODE`; well-formed but
/// non-canonical input is `E_NONCANONICAL`.
///
/// Canonicality is judged by re-encoding the decoded value and comparing bytes
/// at *this* level only — byte strings are opaque here, so `bstr .cbor` items
/// (the COSE protected headers) are validated by decoding them in turn
/// (`specs/bcf-core.md` §3, "recursively to every `bstr .cbor` item").
pub fn decode_canonical(input: &[u8]) -> Result<Value, Error> {
    let mut dec = Decoder { buf: input, pos: 0 };
    let value = dec.value(0)?;
    if dec.pos != input.len() {
        return Err(Error::Decode); // trailing garbage
    }
    if encode(&value) != input {
        return Err(Error::Noncanonical);
    }
    Ok(value)
}

/// Canonically encode a value per RFC 8949 §4.2.1.
///
/// Invariant: callers pass values of bounded nesting depth. Every `Value` in
/// this crate is either produced by [`decode_canonical`] (capped at `MAX_DEPTH`)
/// or built shallowly in place (e.g. the Sig_structure), so the recursion here
/// is bounded transitively. Do not call this on an unbounded hand-built tree.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(i) => {
            if *i >= 0 {
                head(0, *i as u64, out);
            } else {
                head(1, (-1 - *i) as u64, out);
            }
        }
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(3, t.len() as u64, out);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(pairs) => {
            // Canonical order: sort pairs by the bytewise encoding of the key.
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> =
                pairs.iter().map(|(k, v)| (encode(k), encode(v))).collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            head(5, pairs.len() as u64, out);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Null => out.push(0xf6),
        Value::Tag(t, inner) => {
            head(6, *t, out);
            encode_into(inner, out);
        }
    }
}

/// Emit a CBOR head: major type in the top 3 bits, argument in shortest form.
fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let mb = major << 5;
    if arg < 24 {
        out.push(mb | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(mb | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(mb | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(mb | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mb | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::Decode)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Decode)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Decode)?;
        self.pos = end;
        Ok(slice)
    }

    /// Read the argument for a head whose additional-info is `ai`.
    /// Accepts every length encoding (even non-shortest) so the re-encode
    /// comparison can flag non-shortest forms as non-canonical.
    fn arg(&mut self, ai: u8) -> Result<u64, Error> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => Ok(self.byte()? as u64),
            25 => Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64),
            26 => Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64),
            27 => Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())),
            _ => Err(Error::Decode), // 28..=31 handled before this is called
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Decode); // hostile nesting; never recurse past the bound
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let ai = initial & 0x1f;

        // Indefinite lengths are non-canonical (§3.2); on string/array/map that
        // is the precise diagnosis. On other majors ai=31 is simply malformed.
        if ai == 31 {
            return Err(if (2..=5).contains(&major) {
                Error::Noncanonical
            } else {
                Error::Decode
            });
        }
        if (28..=30).contains(&ai) {
            return Err(Error::Decode);
        }

        match major {
            0 => Ok(Value::Int(self.arg(ai)? as i128)),
            1 => Ok(Value::Int(-1 - self.arg(ai)? as i128)),
            2 => {
                let len = self.arg(ai)? as usize;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.arg(ai)? as usize;
                let bytes = self.take(len)?.to_vec();
                let text = String::from_utf8(bytes).map_err(|_| Error::Decode)?;
                Ok(Value::Text(text))
            }
            4 => {
                let len = self.arg(ai)? as usize;
                // The .min(1024) cap is load-bearing: it stops a lying length
                // prefix from forcing a huge up-front allocation. Do not drop it.
                let mut items = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let len = self.arg(ai)? as usize;
                let mut pairs: Vec<(Value, Value)> = Vec::with_capacity(len.min(1024));
                let mut prev_key: Option<Vec<u8>> = None;
                for _ in 0..len {
                    let k = self.value(depth + 1)?;
                    let v = self.value(depth + 1)?;
                    // Keys MUST be strictly ascending by encoded form (§3.2):
                    // this enforces canonical key order AND rejects duplicate
                    // keys, which re-encode-and-compare alone cannot catch.
                    let key_bytes = encode(&k);
                    if let Some(prev) = &prev_key {
                        if *prev >= key_bytes {
                            return Err(Error::Noncanonical);
                        }
                    }
                    prev_key = Some(key_bytes);
                    pairs.push((k, v));
                }
                Ok(Value::Map(pairs))
            }
            6 => {
                // Only the single outer COSE_Sign tag is allowed (§3.4): a tag
                // anywhere nested is non-canonical for this profile.
                if depth != 0 {
                    return Err(Error::Noncanonical);
                }
                let tag = self.arg(ai)?;
                Ok(Value::Tag(tag, Box::new(self.value(depth + 1)?)))
            }
            7 => match ai {
                22 => Ok(Value::Null),
                25..=27 => Err(Error::Noncanonical), // floats forbidden (§3.4)
                _ => Err(Error::Decode),
            },
            _ => unreachable!("major type is 3 bits"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // R-C Break 1: deeply nested input must be a clean error, never a panic or
    // stack overflow. Nested arrays (0x81 = array of one item) drive the
    // recursion that previously overflowed the stack.
    #[test]
    fn deep_nesting_is_rejected_not_panic() {
        let hostile: Vec<u8> = std::iter::repeat_n(0x81, 100_000)
            .chain(std::iter::once(0x00))
            .collect();
        assert_eq!(decode_canonical(&hostile), Err(Error::Decode));
    }

    // R-C Break 2: a map with duplicate keys is non-canonical and rejected;
    // re-encode-and-compare alone cannot catch this, so the decoder must.
    #[test]
    fn duplicate_map_keys_rejected() {
        // a2 01 10 01 20 = {1: 16, 1: -1}
        let dup = [0xa2, 0x01, 0x10, 0x01, 0x20];
        assert_eq!(decode_canonical(&dup), Err(Error::Noncanonical));
    }

    #[test]
    fn unsorted_map_keys_rejected() {
        // a2 02 00 01 00 = {2: 0, 1: 0} (keys descending)
        let unsorted = [0xa2, 0x02, 0x00, 0x01, 0x00];
        assert_eq!(decode_canonical(&unsorted), Err(Error::Noncanonical));
    }

    #[test]
    fn nested_tag_rejected() {
        // 81 c2 00 = [tag(2) 0] — a tag below the top level
        let nested_tag = [0x81, 0xc2, 0x00];
        assert_eq!(decode_canonical(&nested_tag), Err(Error::Noncanonical));
    }

    #[test]
    fn canonical_roundtrip_holds() {
        // {1: "BCF/1", 6: []} encodes canonically and round-trips.
        let v = Value::Map(vec![
            (Value::Int(1), Value::Text("BCF/1".to_string())),
            (Value::Int(6), Value::Array(vec![])),
        ]);
        let bytes = encode(&v);
        assert_eq!(decode_canonical(&bytes), Ok(v));
    }
}
