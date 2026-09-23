//! Log-only, model-guided selection over exact source records.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::incident_analysis::{ParsedEvent, contains_sensitive_data, parse_event};

const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_INPUT_LINES: usize = 100_000;
const MAX_GROUPS: usize = 4_096;
const GROUPS_PER_PAGE: usize = 64;
const PAGE_SELECTION_LIMIT: usize = 8;
const FINAL_SELECTION_LIMIT: usize = 12;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompactionError {
    InvalidInput,
    InputTooLarge,
    InvalidSelection,
    MissingCredential,
    Provider,
    SensitiveInput,
    LocalContextTooSmall,
}

impl CompactionError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "EVIDENTRAIL_COMPACT_INVALID_INPUT",
            Self::InputTooLarge => "EVIDENTRAIL_COMPACT_INPUT_TOO_LARGE",
            Self::InvalidSelection => "EVIDENTRAIL_COMPACT_INVALID_SELECTION",
            Self::MissingCredential => "EVIDENTRAIL_COMPACT_MISSING_CREDENTIAL",
            Self::Provider => "EVIDENTRAIL_COMPACT_PROVIDER_FAILURE",
            Self::SensitiveInput => "EVIDENTRAIL_COMPACT_SENSITIVE_INPUT",
            Self::LocalContextTooSmall => "EVIDENTRAIL_COMPACT_LOCAL_CONTEXT_TOO_SMALL",
        }
    }
}

pub trait LogGroupSelector {
    fn select(&mut self, request: &Value) -> Result<Vec<String>, CompactionError>;
}

#[derive(Clone, Debug, Serialize)]
pub struct LogPackEntry {
    pub source_id: String,
    pub repeat_count: usize,
    pub raw: String,
    pub last_source_id: Option<String>,
    pub last_raw: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LogPack {
    pub source_line_count: usize,
    pub group_count: usize,
    pub selected: Vec<LogPackEntry>,
    pub observed_graph_edge_count: usize,
    #[serde(skip)]
    retained_events: Vec<ParsedEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExpandedLogLine {
    pub source_id: String,
    pub raw: String,
}

impl LogPack {
    /// Expand only a line ID advertised by this pack. The result is copied
    /// from retained input records and bounded before any bytes are returned.
    pub fn expand(
        &self,
        source_id: &str,
        before: usize,
        after: usize,
        max_bytes: usize,
    ) -> Result<Vec<ExpandedLogLine>, CompactionError> {
        if before > 128 || after > 128 || max_bytes == 0 || max_bytes > MAX_OUTPUT_BYTES {
            return Err(CompactionError::InvalidInput);
        }
        let advertised = self.selected.iter().any(|entry| {
            entry.source_id == source_id || entry.last_source_id.as_deref() == Some(source_id)
        });
        if !advertised {
            return Err(CompactionError::InvalidSelection);
        }
        let index = source_id
            .strip_prefix('L')
            .and_then(|value| value.parse::<usize>().ok())
            .and_then(|value| value.checked_sub(1))
            .filter(|index| *index < self.retained_events.len())
            .ok_or(CompactionError::InvalidInput)?;
        let start = index.saturating_sub(before);
        let end = index
            .saturating_add(after)
            .saturating_add(1)
            .min(self.retained_events.len());
        let mut total_bytes = 0usize;
        let mut expanded = Vec::new();
        for event in &self.retained_events[start..end] {
            if contains_sensitive_data(&event.raw) {
                return Err(CompactionError::SensitiveInput);
            }
            total_bytes = total_bytes.saturating_add(event.raw.len());
            if total_bytes > max_bytes {
                return Err(CompactionError::InputTooLarge);
            }
            expanded.push(ExpandedLogLine {
                source_id: event.id.clone(),
                raw: event.raw.clone(),
            });
        }
        Ok(expanded)
    }
}

#[derive(Clone)]
struct LogGroup {
    service: String,
    role: &'static str,
    event_indexes: Vec<usize>,
}

#[derive(Default)]
struct ObservedEdge {
    count: usize,
    source_ids: Vec<String>,
}

/// Every selected line is copied from the input. The selector can name only
/// advertised group IDs; it cannot supply text or change repeat counts.
pub fn compact_logs(
    logs: &[u8],
    task: &str,
    selector: &mut impl LogGroupSelector,
) -> Result<LogPack, CompactionError> {
    if logs.is_empty() || task.trim().is_empty() {
        return Err(CompactionError::InvalidInput);
    }
    if logs.len() > MAX_INPUT_BYTES || task.len() > 4096 {
        return Err(CompactionError::InputTooLarge);
    }
    let text = std::str::from_utf8(logs).map_err(|_| CompactionError::InvalidInput)?;
    let events = text
        .lines()
        .enumerate()
        .map(|(index, raw)| parse_event(index + 1, raw))
        .collect::<Vec<_>>();
    if events.len() > MAX_INPUT_LINES {
        return Err(CompactionError::InputTooLarge);
    }
    let groups = group_events(&events)?;
    let graph = observed_graph(&events);
    let mut candidates = (0..groups.len()).collect::<Vec<_>>();
    while candidates.len() > GROUPS_PER_PAGE {
        let mut reduced = Vec::new();
        for page in candidates.chunks(GROUPS_PER_PAGE) {
            reduced.extend(select_page(
                page,
                &groups,
                &events,
                &graph,
                task,
                PAGE_SELECTION_LIMIT,
                selector,
            )?);
        }
        candidates = reduced;
    }
    let mut selected_indexes = select_page(
        &candidates,
        &groups,
        &events,
        &graph,
        task,
        FINAL_SELECTION_LIMIT,
        selector,
    )?;
    selected_indexes.sort_by_key(|index| groups[*index].event_indexes[0]);
    let mut selected = Vec::new();
    let mut output_bytes = 0usize;
    for index in selected_indexes {
        let group = &groups[index];
        let first = &events[group.event_indexes[0]];
        let last = &events[*group.event_indexes.last().expect("nonempty group")];
        if contains_sensitive_data(&first.raw) || contains_sensitive_data(&last.raw) {
            return Err(CompactionError::SensitiveInput);
        }
        let distinct_last = first.raw != last.raw;
        output_bytes = output_bytes
            .saturating_add(first.raw.len())
            .saturating_add(if distinct_last { last.raw.len() } else { 0 });
        if output_bytes > MAX_OUTPUT_BYTES {
            return Err(CompactionError::InputTooLarge);
        }
        selected.push(LogPackEntry {
            source_id: first.id.clone(),
            repeat_count: group.event_indexes.len(),
            raw: first.raw.clone(),
            last_source_id: distinct_last.then(|| last.id.clone()),
            last_raw: distinct_last.then(|| last.raw.clone()),
        });
    }
    Ok(LogPack {
        source_line_count: events.len(),
        group_count: groups.len(),
        selected,
        observed_graph_edge_count: graph.len(),
        retained_events: events,
    })
}

fn group_events(events: &[ParsedEvent]) -> Result<Vec<LogGroup>, CompactionError> {
    let mut grouped = BTreeMap::<(String, &'static str, String), LogGroup>::new();
    for (index, event) in events.iter().enumerate() {
        grouped
            .entry((event.service.clone(), event.role, event.fingerprint.clone()))
            .or_insert_with(|| LogGroup {
                service: event.service.clone(),
                role: event.role,
                event_indexes: Vec::new(),
            })
            .event_indexes
            .push(index);
    }
    let mut groups = grouped.into_values().collect::<Vec<_>>();
    groups.sort_by_key(|group| group.event_indexes[0]);
    if groups.len() > MAX_GROUPS {
        return Err(CompactionError::InputTooLarge);
    }
    Ok(groups)
}

fn observed_graph(events: &[ParsedEvent]) -> BTreeMap<(String, String), ObservedEdge> {
    let mut edges = BTreeMap::<(String, String), ObservedEdge>::new();
    for event in events {
        let Ok(value) = serde_json::from_str::<Value>(&event.raw) else {
            continue;
        };
        let target = [
            "peer.service",
            "peer_service",
            "target_service",
            "downstream_service",
        ]
        .iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .or_else(|| value.pointer("/peer/service").and_then(Value::as_str));
        let Some(target) = target.filter(|name| valid_service(name)) else {
            continue;
        };
        if event.service == "unknown" || event.service == target {
            continue;
        }
        let edge = edges
            .entry((event.service.clone(), target.to_owned()))
            .or_default();
        edge.count += 1;
        if edge.source_ids.len() < 3 {
            edge.source_ids.push(event.id.clone());
        }
    }
    edges
}

fn valid_service(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn select_page(
    indexes: &[usize],
    groups: &[LogGroup],
    events: &[ParsedEvent],
    graph: &BTreeMap<(String, String), ObservedEdge>,
    task: &str,
    limit: usize,
    selector: &mut impl LogGroupSelector,
) -> Result<Vec<usize>, CompactionError> {
    if indexes.is_empty() {
        return Ok(Vec::new());
    }
    let cards = indexes
        .iter()
        .map(|index| {
            let group = &groups[*index];
            let first = &events[group.event_indexes[0]];
            let last = &events[*group.event_indexes.last().expect("nonempty group")];
            let outgoing = graph
                .iter()
                .filter(|((from, _), _)| from == &group.service)
                .take(8)
                .map(|((_, to), edge)| json!({"service": to, "count": edge.count, "source_ids": edge.source_ids}))
                .collect::<Vec<_>>();
            json!({
                "id": format!("G{}", index + 1),
                "service": group.service,
                "role": group.role,
                "count": group.event_indexes.len(),
                "first": {"id": first.id, "line": safe_sample(&first.raw)},
                "last": {"id": last.id, "line": safe_sample(&last.raw)},
                "observed_targets": outgoing,
            })
        })
        .collect::<Vec<_>>();
    let requested = selector.select(&json!({
        "task": task,
        "groups": cards,
        "max_selected_groups": limit,
        "boundary": "Graph targets are explicit fields from source logs, not causal proof. Select only advertised IDs."
    }))?;
    if requested.len() > limit {
        return Err(CompactionError::InvalidSelection);
    }
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    for id in requested {
        let index = id
            .strip_prefix('G')
            .and_then(|value| value.parse::<usize>().ok())
            .and_then(|value| value.checked_sub(1))
            .ok_or(CompactionError::InvalidSelection)?;
        if !indexes.contains(&index) || !seen.insert(index) {
            return Err(CompactionError::InvalidSelection);
        }
        selected.push(index);
    }
    Ok(selected)
}

fn truncate(value: &str, max: usize) -> &str {
    let mut end = value.len().min(max);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn safe_sample(raw: &str) -> &str {
    if contains_sensitive_data(raw) {
        "[sensitive log line omitted from model input]"
    } else {
        truncate(raw, 160)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ErrorSelector;

    impl LogGroupSelector for ErrorSelector {
        fn select(&mut self, request: &Value) -> Result<Vec<String>, CompactionError> {
            let groups = request["groups"].as_array().unwrap();
            Ok(groups
                .iter()
                .filter(|group| group["role"] == "error")
                .map(|group| group["id"].as_str().unwrap().to_owned())
                .take(request["max_selected_groups"].as_u64().unwrap() as usize)
                .collect())
        }
    }

    #[test]
    fn returns_exact_relevant_lines_after_grouping_noisy_logs() {
        let mut logs = String::new();
        for index in 0..500 {
            logs.push_str(&format!("[ads] WARN: refresh retry trace_id={index}\n"));
        }
        logs.push_str("[checkout] ERROR: payment timed out\n");
        let pack = compact_logs(logs.as_bytes(), "checkout failure", &mut ErrorSelector).unwrap();
        assert_eq!(pack.source_line_count, 501);
        assert_eq!(pack.group_count, 2);
        assert_eq!(pack.selected.len(), 1);
        assert_eq!(pack.selected[0].source_id, "L501");
        assert_eq!(pack.selected[0].raw, "[checkout] ERROR: payment timed out");
    }

    #[test]
    fn graph_uses_explicit_log_fields_and_never_infers_from_cooccurrence() {
        let logs = b"{\"service\":\"checkout\",\"peer.service\":\"database\",\"level\":\"error\",\"message\":\"write failed\"}\n{\"service\":\"database\",\"level\":\"error\",\"message\":\"disk full\"}\n";
        let pack = compact_logs(logs, "checkout failure", &mut ErrorSelector).unwrap();
        assert_eq!(pack.observed_graph_edge_count, 1);
        assert_eq!(pack.selected.len(), 2);
    }

    #[test]
    fn model_selection_reaches_a_rare_failure_on_the_last_page() {
        let mut logs = String::new();
        for index in 0..200 {
            logs.push_str(&format!("[api] INFO: distinct event label_{index}\n"));
        }
        logs.push_str("[database] ERROR: disk full\n");
        let pack = compact_logs(logs.as_bytes(), "find failure", &mut ErrorSelector).unwrap();
        assert_eq!(pack.group_count, 201);
        assert_eq!(pack.selected.len(), 1);
        assert_eq!(pack.selected[0].source_id, "L201");
    }

    #[test]
    fn rejects_fabricated_selection_ids() {
        struct Fabricator;
        impl LogGroupSelector for Fabricator {
            fn select(&mut self, _: &Value) -> Result<Vec<String>, CompactionError> {
                Ok(vec!["G999".to_owned()])
            }
        }
        assert!(matches!(
            compact_logs(b"[api] ERROR: failed\n", "failure", &mut Fabricator),
            Err(CompactionError::InvalidSelection)
        ));
    }

    #[test]
    fn sensitive_line_is_not_sent_to_selector_or_returned_as_log_output() {
        struct InspectingSelector;
        impl LogGroupSelector for InspectingSelector {
            fn select(&mut self, request: &Value) -> Result<Vec<String>, CompactionError> {
                let payload = request.to_string();
                assert!(!payload.contains("password=very-secret"));
                assert!(payload.contains("sensitive log line omitted"));
                Ok(vec!["G1".to_owned()])
            }
        }
        assert!(matches!(
            compact_logs(
                b"[api] ERROR: password=very-secret login failed\n",
                "login failure",
                &mut InspectingSelector,
            ),
            Err(CompactionError::SensitiveInput)
        ));
    }

    #[test]
    fn expansion_returns_only_bounded_original_neighbors_of_advertised_line() {
        let logs =
            b"[api] INFO: request began\n[api] ERROR: checkout failed\n[api] INFO: request ended\n";
        let pack = compact_logs(logs, "checkout failure", &mut ErrorSelector).unwrap();
        assert_eq!(pack.selected[0].source_id, "L2");
        let expanded = pack.expand("L2", 1, 1, 1024).unwrap();
        assert_eq!(
            expanded
                .iter()
                .map(|line| (line.source_id.as_str(), line.raw.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("L1", "[api] INFO: request began"),
                ("L2", "[api] ERROR: checkout failed"),
                ("L3", "[api] INFO: request ended"),
            ]
        );
        assert!(matches!(
            pack.expand("L1", 0, 0, 1024),
            Err(CompactionError::InvalidSelection)
        ));
        assert!(matches!(
            pack.expand("L2", 1, 1, 10),
            Err(CompactionError::InputTooLarge)
        ));
    }

    #[test]
    fn expansion_fails_closed_if_neighbor_contains_sensitive_marker() {
        let logs = b"[api] INFO: password=very-secret\n[api] ERROR: checkout failed\n";
        let pack = compact_logs(logs, "checkout failure", &mut ErrorSelector).unwrap();
        assert!(matches!(
            pack.expand("L2", 1, 0, 1024),
            Err(CompactionError::SensitiveInput)
        ));
    }
}
