use evidentrail_core::Event;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    Python,
    JvmDotNet,
    JavaScript,
    Rust,
    Go,
    Compiler,
    Assertion,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PythonPhase {
    Traceback,
    Terminal,
    AwaitTraceback,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GoPhase {
    AwaitGoroutine,
    Frames,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecognitionState {
    family: Family,
    depth: u16,
    python_phase: PythonPhase,
    go_phase: GoPhase,
}

impl RecognitionState {
    pub(crate) const fn depth(self) -> u16 {
        self.depth
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Continuation {
    pub(crate) state: RecognitionState,
}

pub(crate) fn recognized_start(event: &Event, next: Option<&Event>) -> Option<RecognitionState> {
    if !is_joinable_line(event) {
        return None;
    }
    let line = event.payload();
    let next_line = next
        .filter(|event| is_joinable_line(event))
        .map(Event::payload);

    let family = if is_python_traceback(line) {
        Family::Python
    } else if is_rust_panic_start(line) {
        Family::Rust
    } else if is_go_panic_start(line) {
        Family::Go
    } else if is_compiler_strong_start(line)
        || (is_compiler_generic_start(line) && next_line.is_some_and(is_compiler_structural_line))
    {
        Family::Compiler
    } else if is_assertion_start(line)
        || (is_expected_diff_header(line) && next_line.is_some_and(is_actual_diff_header))
    {
        Family::Assertion
    } else if is_jvm_dotnet_explicit_start(line)
        || (is_jvm_dotnet_exception_header(line) && next_line.is_some_and(is_stack_frame))
    {
        Family::JvmDotNet
    } else if is_javascript_error_header(line) && next_line.is_some_and(is_stack_frame) {
        Family::JavaScript
    } else {
        return None;
    };

    Some(RecognitionState {
        family,
        depth: 1,
        python_phase: PythonPhase::Traceback,
        go_phase: GoPhase::AwaitGoroutine,
    })
}

pub(crate) fn recognized_continuation(
    state: RecognitionState,
    event: &Event,
    next: Option<&Event>,
) -> Option<Continuation> {
    if !is_joinable_line(event) {
        return None;
    }
    let line = event.payload();
    let next_line = next
        .filter(|event| is_joinable_line(event))
        .map(Event::payload);
    let mut updated = state;

    let accepted = match state.family {
        Family::Python => python_continuation(&mut updated, line, next_line),
        Family::JvmDotNet => jvm_dotnet_continuation(&mut updated, line, next_line),
        Family::JavaScript => javascript_continuation(&mut updated, line, next_line),
        Family::Rust => rust_continuation(line, next_line),
        Family::Go => go_continuation(&mut updated, line, next_line),
        Family::Compiler => compiler_continuation(line, next_line),
        Family::Assertion => assertion_continuation(line, next_line),
    };
    accepted.then_some(Continuation { state: updated })
}

pub(crate) fn looks_like_orphan_continuation(event: &Event) -> bool {
    if !is_joinable_line(event) {
        return false;
    }
    let line = event.payload();
    is_python_frame(line)
        || is_python_indented_detail(line)
        || is_python_chain_separator(line)
        || is_stack_frame(line)
        || is_nested_cause(line)
        || is_elided_stack_frames(line)
        || is_dotnet_inner_boundary(line)
        || is_rust_backtrace_marker(line)
        || is_rust_frame(line)
        || is_go_goroutine(line)
        || is_go_location(line)
        || is_compiler_structural_line(line)
        || is_diff_continuation(line)
}

pub(crate) fn is_joinable_line(event: &Event) -> bool {
    event.record_state().is_complete()
        && matches!(
            event.terminator(),
            Some(b"\n") | Some(b"\r\n") | Some(b"\r") | Some(b"")
        )
        && !event.payload().contains(&b'\n')
        && !event.payload().contains(&b'\r')
        && is_safe_ascii_line(event.payload())
}

pub(crate) fn is_provider_atomic(event: &Event) -> bool {
    event.record_state().is_complete()
        && (event.terminator().is_none()
            || event.payload().contains(&b'\n')
            || event.payload().contains(&b'\r'))
}

pub(crate) fn is_opaque_line(event: &Event) -> bool {
    !is_safe_ascii_line(event.payload())
}

fn python_continuation(state: &mut RecognitionState, line: &[u8], next: Option<&[u8]>) -> bool {
    match state.python_phase {
        PythonPhase::Traceback => {
            if is_python_frame(line) || is_python_indented_detail(line) {
                true
            } else if is_python_exception_terminal(line) {
                state.python_phase = PythonPhase::Terminal;
                true
            } else if is_python_chain_separator(line) {
                state.depth = state.depth.saturating_add(1);
                state.python_phase = PythonPhase::AwaitTraceback;
                true
            } else {
                is_blank(line)
                    && next.is_some_and(|candidate| {
                        is_python_frame(candidate) || is_python_exception_terminal(candidate)
                    })
            }
        }
        PythonPhase::Terminal => {
            if is_python_chain_separator(line) {
                state.depth = state.depth.saturating_add(1);
                state.python_phase = PythonPhase::AwaitTraceback;
                true
            } else {
                is_blank(line) && next.is_some_and(is_python_chain_separator)
            }
        }
        PythonPhase::AwaitTraceback => {
            if is_python_traceback(line) {
                state.python_phase = PythonPhase::Traceback;
                true
            } else {
                is_blank(line) && next.is_some_and(is_python_traceback)
            }
        }
    }
}

fn jvm_dotnet_continuation(state: &mut RecognitionState, line: &[u8], next: Option<&[u8]>) -> bool {
    if is_nested_cause(line) || is_dotnet_inner_boundary(line) {
        state.depth = state.depth.saturating_add(1);
        true
    } else if is_stack_frame(line) || is_elided_stack_frames(line) {
        true
    } else {
        is_blank(line)
            && next.is_some_and(|candidate| {
                is_stack_frame(candidate)
                    || is_nested_cause(candidate)
                    || is_dotnet_inner_boundary(candidate)
            })
    }
}

fn javascript_continuation(state: &mut RecognitionState, line: &[u8], next: Option<&[u8]>) -> bool {
    if is_nested_cause(line) {
        state.depth = state.depth.saturating_add(1);
        true
    } else if is_stack_frame(line) || is_elided_stack_frames(line) {
        true
    } else {
        is_blank(line)
            && next.is_some_and(|candidate| is_stack_frame(candidate) || is_nested_cause(candidate))
    }
}

fn rust_continuation(line: &[u8], next: Option<&[u8]>) -> bool {
    is_rust_backtrace_marker(line)
        || is_rust_frame(line)
        || is_rust_panic_detail(line)
        || (is_blank(line)
            && next.is_some_and(|candidate| {
                is_rust_backtrace_marker(candidate) || is_rust_frame(candidate)
            }))
}

fn go_continuation(state: &mut RecognitionState, line: &[u8], next: Option<&[u8]>) -> bool {
    if is_go_goroutine(line) {
        state.depth = state.depth.saturating_add(1);
        state.go_phase = GoPhase::Frames;
        true
    } else if state.go_phase == GoPhase::Frames
        && (is_go_function(line) || is_go_location(line) || is_go_created_by(line))
    {
        true
    } else {
        is_blank(line) && next.is_some_and(is_go_goroutine)
    }
}

fn compiler_continuation(line: &[u8], next: Option<&[u8]>) -> bool {
    is_compiler_structural_line(line)
        || (is_blank(line) && next.is_some_and(is_compiler_structural_line))
}

fn assertion_continuation(line: &[u8], next: Option<&[u8]>) -> bool {
    is_assertion_detail(line)
        || is_diff_continuation(line)
        || (is_blank(line)
            && next.is_some_and(|candidate| {
                is_assertion_detail(candidate) || is_diff_continuation(candidate)
            }))
}

fn is_safe_ascii_line(line: &[u8]) -> bool {
    line.iter()
        .all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte))
}

fn is_blank(line: &[u8]) -> bool {
    line.iter().all(u8::is_ascii_whitespace)
}

fn is_python_traceback(line: &[u8]) -> bool {
    line == b"Traceback (most recent call last):"
}

fn is_python_frame(line: &[u8]) -> bool {
    line.starts_with(b"  File \"") || line.starts_with(b"  File '")
}

fn is_python_indented_detail(line: &[u8]) -> bool {
    line.starts_with(b"    ") || line.starts_with(b"\t")
}

fn is_python_exception_terminal(line: &[u8]) -> bool {
    if line.first().is_some_and(u8::is_ascii_whitespace) || line.is_empty() {
        return false;
    }
    let head = token_before_message(line);
    head.ends_with(b"Error")
        || head.ends_with(b"Exception")
        || matches!(
            head,
            b"KeyboardInterrupt" | b"SystemExit" | b"GeneratorExit"
        )
}

fn is_python_chain_separator(line: &[u8]) -> bool {
    matches!(
        line,
        b"During handling of the above exception, another exception occurred:"
            | b"The above exception was the direct cause of the following exception:"
    )
}

fn is_jvm_dotnet_explicit_start(line: &[u8]) -> bool {
    line.starts_with(b"Exception in thread \"")
        || line.starts_with(b"Unhandled exception.")
        || line.starts_with(b"Unhandled Exception:")
}

fn is_jvm_dotnet_exception_header(line: &[u8]) -> bool {
    if line.first().is_some_and(u8::is_ascii_whitespace) {
        return false;
    }
    let head = token_before_message(line);
    head.contains(&b'.') && (head.ends_with(b"Exception") || head.ends_with(b"Error"))
}

fn is_javascript_error_header(line: &[u8]) -> bool {
    let head = token_before_message(line);
    matches!(
        head,
        b"Error"
            | b"TypeError"
            | b"ReferenceError"
            | b"RangeError"
            | b"SyntaxError"
            | b"URIError"
            | b"EvalError"
            | b"AggregateError"
    )
}

fn is_stack_frame(line: &[u8]) -> bool {
    let leading = line
        .iter()
        .take_while(|byte| **byte == b' ' || **byte == b'\t')
        .count();
    leading > 0 && line[leading..].starts_with(b"at ")
}

fn is_nested_cause(line: &[u8]) -> bool {
    let trimmed = trim_ascii_start(line);
    trimmed.starts_with(b"Caused by:")
        || trimmed.starts_with(b"Suppressed:")
        || trimmed.starts_with(b"Wrapped by:")
}

fn is_elided_stack_frames(line: &[u8]) -> bool {
    let trimmed = trim_ascii_start(line);
    trimmed.starts_with(b"... ") && trimmed.ends_with(b" more")
}

fn is_dotnet_inner_boundary(line: &[u8]) -> bool {
    let trimmed = trim_ascii_start(line);
    trimmed.starts_with(b"---> ") || trimmed == b"--- End of inner exception stack trace ---"
}

fn is_rust_panic_start(line: &[u8]) -> bool {
    line.starts_with(b"panicked at ")
        || (line.starts_with(b"thread '") && contains_bytes(line, b"' panicked at "))
        || (line.starts_with(b"thread \"") && contains_bytes(line, b"\" panicked at "))
}

fn is_rust_backtrace_marker(line: &[u8]) -> bool {
    trim_ascii_start(line) == b"stack backtrace:"
}

fn is_rust_frame(line: &[u8]) -> bool {
    let trimmed = trim_ascii_start(line);
    let digits = trimmed
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let location = trimmed.strip_prefix(b"at ");
    (digits > 0 && trimmed.get(digits) == Some(&b':'))
        || (trimmed.len() < line.len()
            && location.is_some_and(|value| {
                value.contains(&b'/') || value.contains(&b'\\') || value.contains(&b':')
            }))
}

fn is_rust_panic_detail(line: &[u8]) -> bool {
    let trimmed = trim_ascii_start(line);
    trimmed.starts_with(b"note: run with ")
        || trimmed.starts_with(b"left:")
        || trimmed.starts_with(b"right:")
}

fn is_go_panic_start(line: &[u8]) -> bool {
    line.starts_with(b"panic:") || line.starts_with(b"fatal error:")
}

fn is_go_goroutine(line: &[u8]) -> bool {
    let trimmed = trim_ascii_start(line);
    if !trimmed.starts_with(b"goroutine ") || !trimmed.ends_with(b":") {
        return false;
    }
    let after_prefix = &trimmed[b"goroutine ".len()..];
    let digits = after_prefix
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    digits > 0 && after_prefix.get(digits) == Some(&b' ')
}

fn is_go_function(line: &[u8]) -> bool {
    !line.is_empty()
        && !line.first().is_some_and(u8::is_ascii_whitespace)
        && line.ends_with(b")")
        && line.contains(&b'(')
        && !line.contains(&b' ')
}

fn is_go_location(line: &[u8]) -> bool {
    if !line.first().is_some_and(u8::is_ascii_whitespace) {
        return false;
    }
    let trimmed = trim_ascii_start(line);
    contains_bytes(trimmed, b".go:")
}

fn is_go_created_by(line: &[u8]) -> bool {
    trim_ascii_start(line).starts_with(b"created by ")
}

fn is_compiler_strong_start(line: &[u8]) -> bool {
    line.starts_with(b"error[")
        || line.starts_with(b"warning[")
        || line.starts_with(b"fatal error C")
}

fn is_compiler_generic_start(line: &[u8]) -> bool {
    line.starts_with(b"error:") || line.starts_with(b"warning:")
}

fn is_compiler_structural_line(line: &[u8]) -> bool {
    let trimmed = trim_ascii_start(line);
    if trimmed.starts_with(b"-->")
        || trimmed.starts_with(b":::")
        || trimmed.starts_with(b"= note:")
        || trimmed.starts_with(b"= help:")
        || trimmed.starts_with(b"help:")
        || trimmed.starts_with(b"note:")
        || trimmed.starts_with(b"^")
    {
        return true;
    }
    if trimmed.starts_with(b"|") {
        return true;
    }
    let digits = trimmed
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    digits > 0 && trim_ascii_start(&trimmed[digits..]).starts_with(b"|")
}

fn is_assertion_start(line: &[u8]) -> bool {
    line.starts_with(b"AssertionError")
        || line.starts_with(b"AssertionFailedError")
        || line.starts_with(b"org.opentest4j.AssertionFailedError")
        || line.starts_with(b"assertion failed:")
        || (line.starts_with(b"assertion ") && line.ends_with(b" failed"))
}

fn is_assertion_detail(line: &[u8]) -> bool {
    let trimmed = trim_ascii_start(line);
    trimmed.starts_with(b"left:")
        || trimmed.starts_with(b"right:")
        || trimmed.starts_with(b"expected:")
        || trimmed.starts_with(b"actual:")
        || trimmed.starts_with(b"Expected:")
        || trimmed.starts_with(b"Actual:")
}

fn is_expected_diff_header(line: &[u8]) -> bool {
    line.starts_with(b"--- expected") || line.starts_with(b"--- Expected")
}

fn is_actual_diff_header(line: &[u8]) -> bool {
    line.starts_with(b"+++ actual") || line.starts_with(b"+++ Actual")
}

fn is_diff_continuation(line: &[u8]) -> bool {
    is_expected_diff_header(line)
        || is_actual_diff_header(line)
        || line.starts_with(b"@@ ")
        || line.starts_with(b"+ ")
        || line.starts_with(b"- ")
        || line.starts_with(b">")
        || line.starts_with(b"<")
}

fn token_before_message(line: &[u8]) -> &[u8] {
    let end = line
        .iter()
        .position(|byte| *byte == b':' || byte.is_ascii_whitespace())
        .unwrap_or(line.len());
    &line[..end]
}

fn trim_ascii_start(mut line: &[u8]) -> &[u8] {
    while line.first().is_some_and(u8::is_ascii_whitespace) {
        line = &line[1..];
    }
    line
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
