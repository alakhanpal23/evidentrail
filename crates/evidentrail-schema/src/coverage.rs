use std::fmt;

use crate::PatternId;

/// Exactly one presentation disposition for every persisted authorized event.
///
/// Policy-omitted source records never become events and therefore cannot
/// appear in this vocabulary.
#[derive(Clone, PartialEq, Eq)]
pub enum PresentationDisposition {
    ShownVerbatim,
    PatternRepresented { pattern_id: PatternId },
    RetainedRaw,
}

impl PresentationDisposition {
    /// Stable contentless disposition code suitable for diagnostics.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ShownVerbatim => "shown_verbatim",
            Self::PatternRepresented { .. } => "pattern_represented",
            Self::RetainedRaw => "retained_raw",
        }
    }
}

impl fmt::Debug for PresentationDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PresentationDisposition")
            .field("code", &self.code())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PresentationCounts {
    pub shown_verbatim: usize,
    pub pattern_represented: usize,
    pub retained_raw: usize,
}

impl PresentationCounts {
    #[must_use]
    pub const fn persisted(self) -> usize {
        self.shown_verbatim + self.pattern_represented + self.retained_raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presentation_has_exactly_three_accounting_classes() {
        let dispositions = [
            PresentationDisposition::ShownVerbatim,
            PresentationDisposition::PatternRepresented {
                pattern_id: PatternId::from_bytes([0x11; 32]),
            },
            PresentationDisposition::RetainedRaw,
        ];

        assert_eq!(
            dispositions
                .iter()
                .map(PresentationDisposition::code)
                .collect::<Vec<_>>(),
            vec!["shown_verbatim", "pattern_represented", "retained_raw"]
        );
        assert_eq!(
            PresentationCounts {
                shown_verbatim: 1,
                pattern_represented: 2,
                retained_raw: 3,
            }
            .persisted(),
            6
        );
    }

    #[test]
    fn presentation_debug_hides_pattern_identity() {
        const CANARY_BYTE: u8 = 0x99;
        let disposition = PresentationDisposition::PatternRepresented {
            pattern_id: PatternId::from_bytes([CANARY_BYTE; 32]),
        };
        let rendered = format!("{disposition:?}");

        assert_eq!(
            rendered,
            "PresentationDisposition { code: \"pattern_represented\" }"
        );
        assert!(!rendered.contains(&format!("{CANARY_BYTE:02x}").repeat(4)));
    }
}
