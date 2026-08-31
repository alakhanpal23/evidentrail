use std::error::Error as StdError;
use std::fmt;

/// Stable, contentless public failure classes shared by all wire families.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WireErrorV1 {
    EmptyDocument,
    DocumentTooLarge,
    Malformed,
    NonCanonical,
    UnsupportedContract,
    UnsupportedVersion,
    SemanticallyInvalid,
    IdentityMismatch,
    CrossContext,
    ReissueRequired,
    CanonicalizationFailed,
}

impl WireErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyDocument => "EVIDENTRAIL_WIRE_EMPTY_DOCUMENT",
            Self::DocumentTooLarge => "EVIDENTRAIL_WIRE_DOCUMENT_TOO_LARGE",
            Self::Malformed => "EVIDENTRAIL_WIRE_MALFORMED",
            Self::NonCanonical => "EVIDENTRAIL_WIRE_NONCANONICAL",
            Self::UnsupportedContract => "EVIDENTRAIL_WIRE_UNSUPPORTED_CONTRACT",
            Self::UnsupportedVersion => "EVIDENTRAIL_WIRE_UNSUPPORTED_VERSION",
            Self::SemanticallyInvalid => "EVIDENTRAIL_WIRE_SEMANTICALLY_INVALID",
            Self::IdentityMismatch => "EVIDENTRAIL_WIRE_IDENTITY_MISMATCH",
            Self::CrossContext => "EVIDENTRAIL_WIRE_CROSS_CONTEXT",
            Self::ReissueRequired => "EVIDENTRAIL_WIRE_REISSUE_REQUIRED",
            Self::CanonicalizationFailed => "EVIDENTRAIL_WIRE_CANONICALIZATION_FAILED",
        }
    }
}

impl fmt::Debug for WireErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireErrorV1")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for WireErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for WireErrorV1 {}

/// Contentless failures produced while encoding or verifying a local-file
/// query-plan wire object.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PlanVerificationError {
    EmptyDocument,
    DocumentTooLarge,
    MalformedDocument,
    UnsupportedContract,
    UnsupportedVersion,
    NonCanonicalDocument,
    UnsupportedSourceProof,
    InvalidBinaryValue,
    InvalidHashToken,
    InvalidInteger,
    InvalidLocator,
    InvalidRuntimeProfile,
    InvalidTimestamp,
    InvalidSemanticMaterial,
    SourceMemberMismatch,
    SourceIdentityDigestMismatch,
    PlanDigestMismatch,
    PlanIdMismatch,
    CanonicalizationFailed,
}

impl PlanVerificationError {
    /// Stable contentless code suitable for diagnostics and tests.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyDocument => "EVIDENTRAIL_WIRE_PLAN_EMPTY_DOCUMENT",
            Self::DocumentTooLarge => "EVIDENTRAIL_WIRE_PLAN_DOCUMENT_TOO_LARGE",
            Self::MalformedDocument => "EVIDENTRAIL_WIRE_PLAN_MALFORMED_DOCUMENT",
            Self::UnsupportedContract => "EVIDENTRAIL_WIRE_PLAN_UNSUPPORTED_CONTRACT",
            Self::UnsupportedVersion => "EVIDENTRAIL_WIRE_PLAN_UNSUPPORTED_VERSION",
            Self::NonCanonicalDocument => "EVIDENTRAIL_WIRE_PLAN_NONCANONICAL_DOCUMENT",
            Self::UnsupportedSourceProof => "EVIDENTRAIL_WIRE_PLAN_UNSUPPORTED_SOURCE_PROOF",
            Self::InvalidBinaryValue => "EVIDENTRAIL_WIRE_PLAN_INVALID_BINARY_VALUE",
            Self::InvalidHashToken => "EVIDENTRAIL_WIRE_PLAN_INVALID_HASH_TOKEN",
            Self::InvalidInteger => "EVIDENTRAIL_WIRE_PLAN_INVALID_INTEGER",
            Self::InvalidLocator => "EVIDENTRAIL_WIRE_PLAN_INVALID_LOCATOR",
            Self::InvalidRuntimeProfile => "EVIDENTRAIL_WIRE_PLAN_INVALID_RUNTIME_PROFILE",
            Self::InvalidTimestamp => "EVIDENTRAIL_WIRE_PLAN_INVALID_TIMESTAMP",
            Self::InvalidSemanticMaterial => "EVIDENTRAIL_WIRE_PLAN_INVALID_SEMANTIC_MATERIAL",
            Self::SourceMemberMismatch => "EVIDENTRAIL_WIRE_PLAN_SOURCE_MEMBER_MISMATCH",
            Self::SourceIdentityDigestMismatch => {
                "EVIDENTRAIL_WIRE_PLAN_SOURCE_IDENTITY_DIGEST_MISMATCH"
            }
            Self::PlanDigestMismatch => "EVIDENTRAIL_WIRE_PLAN_DIGEST_MISMATCH",
            Self::PlanIdMismatch => "EVIDENTRAIL_WIRE_PLAN_ID_MISMATCH",
            Self::CanonicalizationFailed => "EVIDENTRAIL_WIRE_PLAN_CANONICALIZATION_FAILED",
        }
    }
}

impl fmt::Debug for PlanVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanVerificationError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for PlanVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl StdError for PlanVerificationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_stable_and_contentless() {
        let errors = [
            PlanVerificationError::EmptyDocument,
            PlanVerificationError::DocumentTooLarge,
            PlanVerificationError::MalformedDocument,
            PlanVerificationError::UnsupportedContract,
            PlanVerificationError::UnsupportedVersion,
            PlanVerificationError::NonCanonicalDocument,
            PlanVerificationError::UnsupportedSourceProof,
            PlanVerificationError::InvalidBinaryValue,
            PlanVerificationError::InvalidHashToken,
            PlanVerificationError::InvalidInteger,
            PlanVerificationError::InvalidLocator,
            PlanVerificationError::InvalidRuntimeProfile,
            PlanVerificationError::InvalidTimestamp,
            PlanVerificationError::InvalidSemanticMaterial,
            PlanVerificationError::SourceMemberMismatch,
            PlanVerificationError::SourceIdentityDigestMismatch,
            PlanVerificationError::PlanDigestMismatch,
            PlanVerificationError::PlanIdMismatch,
            PlanVerificationError::CanonicalizationFailed,
        ];

        for error in errors {
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert_eq!(display, error.code());
            assert!(display.starts_with("EVIDENTRAIL_WIRE_PLAN_"));
            assert!(debug.contains(error.code()));
            assert!(!debug.contains("CANARY_/private/log"));
        }
    }
}
