//! Conservative screening before original log bytes reach a model or agent.

pub(crate) fn contains_sensitive_data(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if [
        "password=",
        "passwd=",
        "api_key=",
        "access_token=",
        "secret=",
        "authorization:",
        "dsn=",
        "bearer ",
        "-----begin private key-----",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
    {
        return true;
    }
    [
        "password",
        "passwd",
        "api_key",
        "apikey",
        "access_token",
        "accesstoken",
        "refresh_token",
        "session_token",
        "secret",
        "client_secret",
        "private_key",
        "authorization",
        "token",
        "dsn",
        "connection_string",
        "aws_access_key_id",
        "aws_secret_access_key",
    ]
    .iter()
    .any(|key| {
        let quoted = format!("\"{key}\"");
        lower
            .match_indices(&quoted)
            .any(|(start, _)| lower[start + quoted.len()..].trim_start().starts_with(':'))
    })
}
