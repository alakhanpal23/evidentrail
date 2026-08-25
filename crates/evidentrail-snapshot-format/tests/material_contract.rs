use std::collections::VecDeque;

use evidentrail_snapshot_format::{
    EntropySourceFailureV1, EntropySourceV1, FrameCommitmentV1, FrameHeaderV1, FrameObjectKindV1,
    ManifestHeaderV1, OsEntropyV1, RESULT_DEK_BYTES_V1, ResultCryptoMaterialV1, ResultDekV1,
    SegmentHeaderV1, SnapshotFormatErrorV1, canonical_frame_aad_v1, open_frame_v1,
    open_manifest_v1, seal_frame_v1, seal_manifest_v1, segment_start_commitment_v1,
};

enum EntropyStep {
    Bytes(Vec<u8>),
    Failure,
}

struct ScriptedEntropy {
    steps: VecDeque<EntropyStep>,
}

impl ScriptedEntropy {
    fn new(steps: impl IntoIterator<Item = EntropyStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
        }
    }
}

impl EntropySourceV1 for ScriptedEntropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropySourceFailureV1> {
        match self.steps.pop_front() {
            Some(EntropyStep::Bytes(bytes)) if bytes.len() == destination.len() => {
                destination.copy_from_slice(&bytes);
                Ok(())
            }
            Some(EntropyStep::Bytes(_) | EntropyStep::Failure) | None => {
                Err(EntropySourceFailureV1::Unavailable)
            }
        }
    }
}

fn bytes(length: usize, value: u8) -> EntropyStep {
    EntropyStep::Bytes(vec![value; length])
}

fn valid_material_steps(extra: impl IntoIterator<Item = EntropyStep>) -> Vec<EntropyStep> {
    [bytes(32, 0x11), bytes(RESULT_DEK_BYTES_V1, 0x22)]
        .into_iter()
        .chain(extra)
        .collect()
}

#[test]
fn deterministic_entropy_generates_exact_identity_dek_and_nonce_sequence() {
    let script = valid_material_steps([bytes(24, 0x33), bytes(24, 0x44)]);
    let mut material = ResultCryptoMaterialV1::generate(ScriptedEntropy::new(script)).unwrap();
    assert_eq!(material.result_id().as_bytes(), &[0x11; 32]);
    assert_eq!(material.issued_nonce_count(), 0);

    let frame_nonce = material.issue_frame_nonce().unwrap();
    let manifest_nonce = material.issue_manifest_nonce().unwrap();
    assert_eq!(frame_nonce.as_bytes(), &[0x33; 24]);
    assert_eq!(manifest_nonce.as_bytes(), &[0x44; 24]);
    assert_eq!(material.issued_nonce_count(), 2);

    let replay = valid_material_steps([bytes(24, 0x33), bytes(24, 0x44)]);
    let mut replay = ResultCryptoMaterialV1::generate(ScriptedEntropy::new(replay)).unwrap();
    assert_eq!(replay.result_id(), material.result_id());
    assert_eq!(replay.issue_frame_nonce().unwrap(), frame_nonce);
    assert_eq!(replay.issue_manifest_nonce().unwrap(), manifest_nonce);
}

#[test]
fn entropy_failures_and_all_zero_outputs_fail_closed_without_nonce_advance() {
    assert_eq!(
        ResultCryptoMaterialV1::generate(ScriptedEntropy::new([EntropyStep::Failure])).unwrap_err(),
        SnapshotFormatErrorV1::EntropyUnavailable
    );
    assert_eq!(
        ResultCryptoMaterialV1::generate(ScriptedEntropy::new([
            bytes(32, 0x11),
            EntropyStep::Failure,
        ]))
        .unwrap_err(),
        SnapshotFormatErrorV1::EntropyUnavailable
    );
    assert_eq!(
        ResultCryptoMaterialV1::generate(ScriptedEntropy::new([bytes(32, 0), bytes(32, 1)]))
            .unwrap_err(),
        SnapshotFormatErrorV1::AllZeroEntropyOutput
    );
    assert_eq!(
        ResultCryptoMaterialV1::generate(ScriptedEntropy::new([bytes(32, 1), bytes(32, 0)]))
            .unwrap_err(),
        SnapshotFormatErrorV1::AllZeroEntropyOutput
    );
    assert_eq!(
        ResultDekV1::from_test_bytes([0; RESULT_DEK_BYTES_V1]).unwrap_err(),
        SnapshotFormatErrorV1::AllZeroEntropyOutput
    );

    let script = valid_material_steps([EntropyStep::Failure, bytes(24, 0), bytes(24, 0x55)]);
    let mut material = ResultCryptoMaterialV1::generate(ScriptedEntropy::new(script)).unwrap();
    assert_eq!(
        material.issue_frame_nonce(),
        Err(SnapshotFormatErrorV1::EntropyUnavailable)
    );
    assert_eq!(material.issued_nonce_count(), 0);
    assert_eq!(
        material.issue_manifest_nonce(),
        Err(SnapshotFormatErrorV1::AllZeroEntropyOutput)
    );
    assert_eq!(material.issued_nonce_count(), 0);
    assert_eq!(
        material.issue_frame_nonce().unwrap().as_bytes(),
        &[0x55; 24]
    );
    assert_eq!(material.issued_nonce_count(), 1);
}

#[test]
fn repeated_entropy_and_cross_object_nonce_collision_are_rejected_transactionally() {
    assert_eq!(
        ResultCryptoMaterialV1::generate(ScriptedEntropy::new([bytes(32, 0x77), bytes(32, 0x77),]))
            .unwrap_err(),
        SnapshotFormatErrorV1::RepeatedEntropyOutput
    );

    let script = valid_material_steps([bytes(24, 0x66), bytes(24, 0x66), bytes(24, 0x67)]);
    let mut material = ResultCryptoMaterialV1::generate(ScriptedEntropy::new(script)).unwrap();
    assert_eq!(
        material.issue_frame_nonce().unwrap().as_bytes(),
        &[0x66; 24]
    );
    assert_eq!(material.issued_nonce_count(), 1);
    assert_eq!(
        material.issue_manifest_nonce(),
        Err(SnapshotFormatErrorV1::DuplicateNonce)
    );
    assert_eq!(material.issued_nonce_count(), 1);
    assert_eq!(
        material.issue_manifest_nonce().unwrap().as_bytes(),
        &[0x67; 24]
    );
    assert_eq!(material.issued_nonce_count(), 2);
}

#[test]
fn one_dek_owner_backs_successful_frame_and_manifest_round_trips() {
    let script = valid_material_steps([bytes(24, 0x31), bytes(24, 0x32)]);
    let mut material = ResultCryptoMaterialV1::generate(ScriptedEntropy::new(script)).unwrap();
    let result_id = material.result_id();

    let segment =
        SegmentHeaderV1::new(1, result_id, 0, 1_000, 2_000, FrameCommitmentV1::ZERO).unwrap();
    let frame_payload = [0xff, 0, b'F', b'\n'];
    let frame_header = FrameHeaderV1::new(
        FrameObjectKindV1::AuthorizedOutcome,
        0,
        0,
        u32::try_from(frame_payload.len()).unwrap(),
        material.issue_frame_nonce().unwrap(),
        segment_start_commitment_v1(&segment),
    )
    .unwrap();
    let frame = seal_frame_v1(
        &material.dek().frame_key(),
        &segment,
        frame_header,
        &frame_payload,
    )
    .unwrap();
    assert_eq!(
        open_frame_v1(&material.dek().frame_key(), &segment, &frame)
            .unwrap()
            .as_bytes(),
        frame_payload
    );

    let manifest_payload = [b'M', 0, 0x80, b'\r', b'\n'];
    let manifest_header = ManifestHeaderV1::new(
        1,
        result_id,
        0,
        1_000,
        2_000,
        u32::try_from(manifest_payload.len()).unwrap(),
        material.issue_manifest_nonce().unwrap(),
    )
    .unwrap();
    let manifest = seal_manifest_v1(
        &material.dek().manifest_key(),
        manifest_header,
        &manifest_payload,
    )
    .unwrap();
    assert_eq!(
        open_manifest_v1(&material.dek().manifest_key(), result_id, &manifest,)
            .unwrap()
            .as_bytes(),
        manifest_payload
    );
    assert_eq!(material.issued_nonce_count(), 2);

    // Both typed views authenticate the exact same frozen owner without
    // exposing or independently owning the DEK bytes.
    assert_eq!(
        canonical_frame_aad_v1(&segment, frame.header()).len(),
        evidentrail_snapshot_format::FRAME_AAD_BYTES_V1
    );
}

#[test]
fn os_entropy_implements_the_injected_boundary_without_custom_backend_state() {
    fn assert_source<T: EntropySourceV1>() {}
    assert_source::<OsEntropyV1>();

    let mut source = OsEntropyV1;
    let mut empty = [];
    source.fill_bytes(&mut empty).unwrap();
}

#[test]
fn material_views_and_errors_have_contentless_debug_output() {
    let script = [bytes(32, b'S'), bytes(32, b'K'), bytes(24, b'N')];
    let mut material = ResultCryptoMaterialV1::generate(ScriptedEntropy::new(script)).unwrap();
    let nonce = material.issue_frame_nonce().unwrap();
    let rendered = format!(
        "{material:?} {:?} {:?} {nonce:?} {:?} {:?}",
        material.dek(),
        material.dek().frame_key(),
        EntropySourceFailureV1::Unavailable,
        SnapshotFormatErrorV1::RepeatedEntropyOutput,
    );
    assert!(!rendered.contains("SSSS"));
    assert!(!rendered.contains("KKKK"));
    assert!(!rendered.contains("NNNN"));
    assert!(!rendered.contains("\x11\x11"));
    assert!(!rendered.contains("\x22\x22"));
}
