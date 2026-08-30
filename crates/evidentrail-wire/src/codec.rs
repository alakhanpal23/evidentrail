#[cfg(any(feature = "ledger", feature = "product"))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "product")]
use evidentrail_schema::ResultId;
#[cfg(any(feature = "ledger", feature = "product"))]
use schemars::JsonSchema;
#[cfg(any(feature = "ledger", feature = "product"))]
use serde::{Deserialize, Serialize};

use crate::WireErrorV1;

#[cfg(any(feature = "ledger", feature = "product"))]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BinaryWireV1 {
    encoding: String,
    data: String,
    byte_length: u64,
}

#[cfg(any(feature = "ledger", feature = "product"))]
impl BinaryWireV1 {
    #[cfg(any(feature = "ledger", feature = "product"))]
    pub(crate) fn encode(bytes: &[u8]) -> Result<Self, WireErrorV1> {
        Ok(Self {
            encoding: "base64url-nopad".into(),
            data: URL_SAFE_NO_PAD.encode(bytes),
            byte_length: u64::try_from(bytes.len())
                .map_err(|_| WireErrorV1::SemanticallyInvalid)?,
        })
    }
    #[cfg(any(feature = "ledger", feature = "product"))]
    pub(crate) fn decode(&self) -> Result<Vec<u8>, WireErrorV1> {
        if self.encoding != "base64url-nopad" || self.data.contains('=') {
            return Err(WireErrorV1::SemanticallyInvalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(self.data.as_bytes())
            .map_err(|_| WireErrorV1::SemanticallyInvalid)?;
        if u64::try_from(bytes.len()).ok() != Some(self.byte_length)
            || URL_SAFE_NO_PAD.encode(&bytes) != self.data
        {
            return Err(WireErrorV1::SemanticallyInvalid);
        }
        Ok(bytes)
    }
}

pub(crate) fn parse_hash_token(token: &str, prefix: &str) -> Result<[u8; 32], WireErrorV1> {
    let hex = token
        .strip_prefix(prefix)
        .ok_or(WireErrorV1::SemanticallyInvalid)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, WireErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(WireErrorV1::SemanticallyInvalid),
    }
}

#[cfg(feature = "product")]
pub(crate) fn parse_result_id(token: &str) -> Result<ResultId, WireErrorV1> {
    Ok(ResultId::from_bytes(parse_hash_token(token, "result_")?))
}

#[cfg(any(feature = "ledger", feature = "product"))]
pub(crate) fn parse_timestamp(
    value: &str,
) -> Result<evidentrail_schema::UnixTimestampNanos, WireErrorV1> {
    let parsed = value
        .parse::<i128>()
        .map_err(|_| WireErrorV1::SemanticallyInvalid)?;
    if parsed.to_string() != value {
        return Err(WireErrorV1::SemanticallyInvalid);
    }
    Ok(evidentrail_schema::UnixTimestampNanos::new(parsed))
}
