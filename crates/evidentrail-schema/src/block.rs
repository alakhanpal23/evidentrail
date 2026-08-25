use std::fmt;

/// Stable identity of the framing policy that proposed an atomic block.
///
/// Policy and version are exact opaque bytes. They participate in block
/// identity but are never exposed by diagnostic formatting.
#[derive(Clone, PartialEq, Eq)]
pub struct FramingPolicy {
    policy: Vec<u8>,
    version: Vec<u8>,
}

impl FramingPolicy {
    #[must_use]
    pub fn new(policy: impl Into<Vec<u8>>, version: impl Into<Vec<u8>>) -> Self {
        Self {
            policy: policy.into(),
            version: version.into(),
        }
    }

    #[must_use]
    pub fn policy(&self) -> &[u8] {
        &self.policy
    }

    #[must_use]
    pub fn version(&self) -> &[u8] {
        &self.version
    }
}

impl fmt::Debug for FramingPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FramingPolicy")
            .field("policy_bytes", &self.policy.len())
            .field("version_bytes", &self.version.len())
            .finish()
    }
}

/// How the block boundary was established. Core records this declaration but
/// does not inspect content or decide which state is appropriate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    ProviderAtomic,
    Reconstructed,
    Ambiguous,
    FallbackSingleton,
}

impl BlockState {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProviderAtomic => "provider_atomic",
            Self::Reconstructed => "reconstructed",
            Self::Ambiguous => "ambiguous",
            Self::FallbackSingleton => "fallback_singleton",
        }
    }
}

impl fmt::Debug for BlockState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockState")
            .field("code", &self.code())
            .finish()
    }
}

/// Typed confidence vocabulary for an externally proposed block boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BlockConfidence {
    Certain,
    High,
    Medium,
    Low,
    Unknown,
}

impl BlockConfidence {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Certain => "certain",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Debug for BlockConfidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockConfidence")
            .field("code", &self.code())
            .finish()
    }
}
