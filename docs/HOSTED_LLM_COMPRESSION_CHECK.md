# Hosted LLM compression check

The hosted-reader compression check is an optional EvidentrailBench evaluation.
It tests whether a smaller deterministic method artifact preserves a pinned
model's structured diagnosis relative to the full artifact. It does not use an
LLM to create or mutate trusted evidence.

## Evaluation flow

1. Freeze one provider, model, tokenizer, adapter implementation, decoding
   configuration, and resource-cap set in `HostedReaderJsonlAdapterSpecV1`.
2. Build one `HostedReaderJsonlRequestV1` for the full view and one for the
   compressed view. The question, context, and public case must be identical.
3. An out-of-process adapter decodes the message hex, makes exactly one model
   call per request, and emits one canonical response JSON line. Credentials
   stay out of the request, response, receipts, and library process.
4. Parse each response with `HostedReaderJsonlResponseV1::try_parse`.
5. Call `check_hosted_reader_compression_v1` with both inputs and responses.

The check fails unless all of the following hold:

- both responses bind to their exact configuration, request, and public input;
- response JSON and the nested reader answer are canonical and contain no
  unknown fields or tool actions;
- provider-reported usage and observed resource values are present and within
  the frozen caps;
- the compressed method artifact is smaller;
- the provider-reported compressed prompt token count is smaller;
- the complete structured answer bytes are identical, including abstention,
  cause, diagnosis, claims, uncertainty, and citation handles;
- the citation handles retain the same evidence-target semantics; and
- the two calls have distinct digested provider request identities.

## Response JSONL schema

The response is exactly one canonical JSON object followed by one newline. Its
fields, in canonical order, are:

```json
{"schema_version":1,"configuration_artifact_digest":"<64 lowercase hex>","request_artifact_digest":"<64 lowercase hex>","public_input_artifact_digest":"<64 lowercase hex>","response_contract_artifact_digest":"<64 lowercase hex>","provider_request_id_digest":"<64 lowercase hex>","answer":{"schema_version":1,"abstained":false,"abstention_reason":null,"cause_code":"example_cause","cause_granularity":"root_cause","diagnosis":"Evidence-cited diagnosis.","citation_handles":[1],"claim_codes":["example_claim"],"uncertainty_micros":10000,"tool_actions":[]},"usage":{"prompt_tokens":1000,"completion_tokens":100,"total_tokens":1100},"wall_time_nanos":1000000,"direct_process_peak_rss_bytes":1048576}
```

Digest fields use raw SHA-256 bytes encoded as 64 lowercase hexadecimal
characters, without the human-readable `artifact_sha256_` prefix. The provider
request ID must be hashed before emission; raw provider identifiers are not
accepted.

## Trust boundary

Prompt-token counts are provider-reported in V1. The parser verifies arithmetic
and caps but does not claim an independent tokenizer measurement. Consequently,
a passing receipt means `passed_against_full_view_not_production_admission`.
Corpus-level governed truth, deterministic exactness checks, repeatability, and
the existing controlled-admission process remain separate requirements.

No provider or model is selected by the repository. A deployment must review
the chosen provider's data-use terms and implement the out-of-process adapter;
the default product and required CI remain local, deterministic, and
credential-free.
