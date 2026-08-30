use std::error::Error as StdError;
use std::fmt;

use evidentrail_schema::bounds::{
    MAX_AUTHORIZED_RECORD_BYTES, MAX_RECORD_TERMINATOR_BYTES, MAX_TRANSFORMATION_OPERATIONS,
};
use evidentrail_schema::{ContentHash, EventId, PolicyDigest, RecordBytes, TransformationReceiptId};
use sha2::{Digest, Sha256};

use crate::hash::authorized_content_hash;

#[derive(Clone, PartialEq, Eq)]
pub struct ByteRangeReplacementV1 {
    start: u64,
    end: u64,
    replacement: Vec<u8>,
}
impl ByteRangeReplacementV1 {
    #[must_use]
    pub fn new(start: u64, end: u64, replacement: impl Into<Vec<u8>>) -> Self {
        Self {
            start,
            end,
            replacement: replacement.into(),
        }
    }
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }
    #[must_use]
    pub fn replacement(&self) -> &[u8] {
        &self.replacement
    }
}
impl fmt::Debug for ByteRangeReplacementV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByteRangeReplacementV1")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("replacement_byte_count", &self.replacement.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreparedTransformationReceiptV1 {
    id: TransformationReceiptId,
    policy_digest: PolicyDigest,
    operations: Vec<ByteRangeReplacementV1>,
    input_length: u64,
    output_length: u64,
    output_content_hash: ContentHash,
    output_payload_length: u64,
    output_terminator_length: Option<u64>,
}

impl PreparedTransformationReceiptV1 {
    pub fn new(
        policy_digest: PolicyDigest,
        input: &RecordBytes,
        output: &RecordBytes,
        operations: impl IntoIterator<Item = ByteRangeReplacementV1>,
    ) -> Result<Self, TransformationReceiptErrorV1> {
        let operations = operations.into_iter().collect::<Vec<_>>();
        if operations.len() > MAX_TRANSFORMATION_OPERATIONS {
            return Err(TransformationReceiptErrorV1::TooManyOperations);
        }
        if output.payload_len() > MAX_AUTHORIZED_RECORD_BYTES
            || output
                .terminator()
                .is_some_and(|value| value.len() > MAX_RECORD_TERMINATOR_BYTES)
        {
            return Err(TransformationReceiptErrorV1::OutputTooLarge);
        }
        let input_bytes = input.exact_bytes();
        let output_bytes = output.exact_bytes();
        let mut prior_end = 0_u64;
        let mut rebuilt = Vec::with_capacity(output_bytes.len());
        for operation in &operations {
            if operation.start > operation.end
                || operation.end > input_bytes.len() as u64
                || operation.start < prior_end
            {
                return Err(TransformationReceiptErrorV1::InvalidOperationOrder);
            }
            let start = usize::try_from(operation.start)
                .map_err(|_| TransformationReceiptErrorV1::InvalidOperationOrder)?;
            let prior = usize::try_from(prior_end)
                .map_err(|_| TransformationReceiptErrorV1::InvalidOperationOrder)?;
            rebuilt.extend_from_slice(&input_bytes[prior..start]);
            rebuilt.extend_from_slice(&operation.replacement);
            prior_end = operation.end;
        }
        rebuilt.extend_from_slice(
            &input_bytes[usize::try_from(prior_end)
                .map_err(|_| TransformationReceiptErrorV1::InvalidOperationOrder)?..],
        );
        if rebuilt != output_bytes {
            return Err(TransformationReceiptErrorV1::OutputMismatch);
        }
        let input_length = u64::try_from(input_bytes.len())
            .map_err(|_| TransformationReceiptErrorV1::LengthOverflow)?;
        let output_length = u64::try_from(output_bytes.len())
            .map_err(|_| TransformationReceiptErrorV1::LengthOverflow)?;
        let output_payload_length = u64::try_from(output.payload_len())
            .map_err(|_| TransformationReceiptErrorV1::LengthOverflow)?;
        let output_terminator_length = output
            .terminator()
            .map(|value| {
                u64::try_from(value.len()).map_err(|_| TransformationReceiptErrorV1::LengthOverflow)
            })
            .transpose()?;
        let output_content_hash = authorized_content_hash(&output_bytes);
        let id = receipt_id(
            policy_digest,
            &operations,
            input_length,
            output_length,
            output_content_hash,
            output_payload_length,
            output_terminator_length,
        );
        Ok(Self {
            id,
            policy_digest,
            operations,
            input_length,
            output_length,
            output_content_hash,
            output_payload_length,
            output_terminator_length,
        })
    }
    #[must_use]
    pub const fn id(&self) -> TransformationReceiptId {
        self.id
    }
    #[must_use]
    pub const fn policy_digest(&self) -> PolicyDigest {
        self.policy_digest
    }
    #[must_use]
    pub fn operations(&self) -> &[ByteRangeReplacementV1] {
        &self.operations
    }
    #[must_use]
    pub const fn input_length(&self) -> u64 {
        self.input_length
    }
    #[must_use]
    pub const fn output_length(&self) -> u64 {
        self.output_length
    }
    #[must_use]
    pub const fn output_content_hash(&self) -> ContentHash {
        self.output_content_hash
    }
    #[must_use]
    pub const fn output_payload_length(&self) -> u64 {
        self.output_payload_length
    }
    #[must_use]
    pub const fn output_terminator_length(&self) -> Option<u64> {
        self.output_terminator_length
    }
    pub(crate) fn bind(self, resulting_event_id: EventId) -> TransformationReceiptV1 {
        TransformationReceiptV1 {
            prepared: self,
            resulting_event_id,
        }
    }
}

impl fmt::Debug for PreparedTransformationReceiptV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedTransformationReceiptV1")
            .field("operation_count", &self.operations.len())
            .field("input_length", &self.input_length)
            .field("output_length", &self.output_length)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransformationReceiptV1 {
    prepared: PreparedTransformationReceiptV1,
    resulting_event_id: EventId,
}
impl TransformationReceiptV1 {
    #[must_use]
    pub const fn id(&self) -> TransformationReceiptId {
        self.prepared.id()
    }
    #[must_use]
    pub const fn policy_digest(&self) -> PolicyDigest {
        self.prepared.policy_digest()
    }
    #[must_use]
    pub fn operations(&self) -> &[ByteRangeReplacementV1] {
        self.prepared.operations()
    }
    #[must_use]
    pub const fn input_length(&self) -> u64 {
        self.prepared.input_length()
    }
    #[must_use]
    pub const fn output_length(&self) -> u64 {
        self.prepared.output_length()
    }
    #[must_use]
    pub const fn output_content_hash(&self) -> ContentHash {
        self.prepared.output_content_hash()
    }
    #[must_use]
    pub const fn output_payload_length(&self) -> u64 {
        self.prepared.output_payload_length()
    }
    #[must_use]
    pub const fn output_terminator_length(&self) -> Option<u64> {
        self.prepared.output_terminator_length()
    }
    #[must_use]
    pub const fn resulting_event_id(&self) -> EventId {
        self.resulting_event_id
    }
}
impl fmt::Debug for TransformationReceiptV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransformationReceiptV1")
            .field("operation_count", &self.operations().len())
            .field("input_length", &self.input_length())
            .field("output_length", &self.output_length())
            .field("resulting_event_bound", &true)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransformationReceiptErrorV1 {
    TooManyOperations,
    InvalidOperationOrder,
    OutputMismatch,
    OutputTooLarge,
    LengthOverflow,
}
impl TransformationReceiptErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooManyOperations => "EVIDENTRAIL_TRANSFORMATION_TOO_MANY_OPERATIONS",
            Self::InvalidOperationOrder => "EVIDENTRAIL_TRANSFORMATION_INVALID_OPERATION_ORDER",
            Self::OutputMismatch => "EVIDENTRAIL_TRANSFORMATION_OUTPUT_MISMATCH",
            Self::OutputTooLarge => "EVIDENTRAIL_TRANSFORMATION_OUTPUT_TOO_LARGE",
            Self::LengthOverflow => "EVIDENTRAIL_TRANSFORMATION_LENGTH_OVERFLOW",
        }
    }
}
impl fmt::Debug for TransformationReceiptErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransformationReceiptErrorV1")
            .field("code", &self.code())
            .finish()
    }
}
impl fmt::Display for TransformationReceiptErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl StdError for TransformationReceiptErrorV1 {}

fn receipt_id(
    policy: PolicyDigest,
    operations: &[ByteRangeReplacementV1],
    input_length: u64,
    output_length: u64,
    output_hash: ContentHash,
    payload_length: u64,
    terminator_length: Option<u64>,
) -> TransformationReceiptId {
    let mut hasher = Sha256::new();
    update(&mut hasher, b"evidentrail/transformation-receipt/v1");
    update(&mut hasher, policy.as_bytes());
    update(&mut hasher, &input_length.to_le_bytes());
    update(&mut hasher, &output_length.to_le_bytes());
    update(&mut hasher, output_hash.as_bytes());
    update(&mut hasher, &payload_length.to_le_bytes());
    match terminator_length {
        Some(value) => {
            hasher.update([1]);
            update(&mut hasher, &value.to_le_bytes());
        }
        None => hasher.update([0]),
    }
    update(&mut hasher, &(operations.len() as u64).to_le_bytes());
    for operation in operations {
        update(&mut hasher, &operation.start.to_le_bytes());
        update(&mut hasher, &operation.end.to_le_bytes());
        update(&mut hasher, &operation.replacement);
    }
    TransformationReceiptId::from_bytes(hasher.finalize().into())
}
fn update(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacements_are_sorted_nonoverlapping_and_exact() {
        let input = RecordBytes::framed(b"secret=old".to_vec(), b"\r\n".to_vec());
        let output = RecordBytes::framed(b"secret=[redacted]".to_vec(), b"\r\n".to_vec());
        let receipt = PreparedTransformationReceiptV1::new(
            PolicyDigest::from_bytes([7; 32]),
            &input,
            &output,
            [ByteRangeReplacementV1::new(7, 10, b"[redacted]".to_vec())],
        )
        .unwrap();
        assert_eq!(receipt.input_length(), 12);
        assert_eq!(receipt.output_length(), 19);
        assert_eq!(receipt.output_payload_length(), 17);
        assert_eq!(receipt.output_terminator_length(), Some(2));
        assert_eq!(
            receipt.output_content_hash(),
            authorized_content_hash(&output.exact_bytes())
        );
        assert!(!format!("{receipt:?}").contains("secret"));

        let overlap = PreparedTransformationReceiptV1::new(
            PolicyDigest::from_bytes([7; 32]),
            &input,
            &output,
            [
                ByteRangeReplacementV1::new(7, 10, b"x".to_vec()),
                ByteRangeReplacementV1::new(9, 10, b"y".to_vec()),
            ],
        );
        assert_eq!(
            overlap,
            Err(TransformationReceiptErrorV1::InvalidOperationOrder)
        );
    }

    #[test]
    fn output_mismatch_and_identity_mutation_fail() {
        let input = RecordBytes::whole(b"abc".to_vec());
        let output = RecordBytes::whole(b"axc".to_vec());
        assert_eq!(
            PreparedTransformationReceiptV1::new(
                PolicyDigest::from_bytes([1; 32]),
                &input,
                &output,
                [ByteRangeReplacementV1::new(1, 2, b"z".to_vec())]
            ),
            Err(TransformationReceiptErrorV1::OutputMismatch)
        );
        let first = PreparedTransformationReceiptV1::new(
            PolicyDigest::from_bytes([1; 32]),
            &input,
            &output,
            [ByteRangeReplacementV1::new(1, 2, b"x".to_vec())],
        )
        .unwrap();
        let second = PreparedTransformationReceiptV1::new(
            PolicyDigest::from_bytes([2; 32]),
            &input,
            &output,
            [ByteRangeReplacementV1::new(1, 2, b"x".to_vec())],
        )
        .unwrap();
        assert_ne!(first.id(), second.id());
    }
}
