# AI, Analysis, Cache, and Extension Review

## Subsystem Summary

This scope supplies the AI abstraction and 19 registered backends, prompt templates, analysis orchestration, five cache implementations, shared result/analyzer contracts, and a gRPC custom-analyzer client plus configuration validator. `Analysis.RunAnalysis` concurrently executes built-in analyzers; `GetAIResults` optionally replaces each declared `Failure.Sensitive` value, formats a kind-specific prompt, consults a provider/language/input cache key, invokes the configured backend, restores masked values in the returned text, and stores the pre-restoration response as base64. Providers themselves do not sanitize: they transmit the prompt they receive. Custom analyzers are different extensions: K8sGPT sends an empty gRPC `RunRequest` and maps the remote result, without passing cluster or analysis context.

Construction is configuration-driven but not uniformly isolated. `ai.NewClient` selects registered clients from package-global pointers and silently returns OpenAI for unknown names; the stateful registered clients mutate shared singleton state, while `NoOpAIClient` is stateless. `cache.New` similarly returns shared registry pointers for recognized cache types but a fresh `FileBasedCache` for unknown types; normal `GetCacheConfiguration` also constructs fresh cache values. HTTP/AWS/Google/OCI SDKs carry most request mechanics, while several OpenAI-compatible implementations duplicate nearly identical request code. Tests are strongest around recent Anthropic, Azure, Bedrock Converse/Mantle, LiteLLM, orchestration, file cache, and Interplex behavior; many other providers and all cloud object caches lack request/response unit coverage.

## File Records

### `pkg/ai/amazonbedrock.go`
- **Role:** Implements legacy Amazon Bedrock `InvokeModel` support, model-family adapters, regional configuration, and inference-profile lookup.
- **Implementation:** `Configure` loads AWS SDK v2 clients, resolves a fixed model table or an inference-profile ARN, and `GetCompletion` mutates the selected model config, marshals through `bedrock_support.ICompletion`, optionally adds the profile ARN header, invokes, and parses through `IResponse`.
- **Dependencies:** AWS Bedrock management/runtime SDKs, Smithy middleware, `bedrock_support`, environment `AWS_DEFAULT_REGION`, and `IAIConfig`.
- **Quality/Risk:** Model and profile helpers have tests, but invocation/header/error branches are largely untested. The client is mutable and assumes `Configure` preceded use; credential errors are matched by strings, profile parsing takes only the first model, and the shared registry in `iai.go` makes concurrent configuration unsafe.

### `pkg/ai/amazonbedrock_mock_test.go`
- **Role:** Provides testify mocks and verifies inference-profile configuration without live AWS calls.
- **Implementation:** Mock management/runtime interfaces return configured outputs; the test maps a profile ARN to a foundation model and asserts the ARN remains the invocation model name.
- **Dependencies:** AWS SDK v2 types, `bedrock_support`, testify mock/assert.
- **Quality/Risk:** Good isolation for the profile lookup happy path, but the runtime mock is unused here and no malformed, permission, alternate-profile, or invocation-header behavior is exercised.

### `pkg/ai/amazonbedrock_test.go`
- **Role:** Tests model matching, defaults, inference-profile ARN validation, and selected configuration failures.
- **Implementation:** Uses a small injected model table and table-driven exact/trimmed/case-insensitive lookup cases; some tests intentionally depend on missing live AWS access producing an error.
- **Dependencies:** `bedrock_support` adapters and testify assertions.
- **Quality/Risk:** Lookup and ARN syntax coverage is useful, but `TestBedrockInferenceProfileARN` is environment-dependent and only asserts an error. One “inference-policy” case is not a valid profile ARN and therefore does not cover the behavior its name suggests.

### `pkg/ai/amazonbedrockconverse.go`
- **Role:** Implements Bedrock's model-agnostic Converse API.
- **Implementation:** Accepts any nonempty trimmed model identifier, loads an AWS runtime client, sends one user text block with inference controls, omits `topP` for model IDs containing `claude`, and concatenates returned text blocks.
- **Dependencies:** AWS SDK v2 config/runtime/types, `AWS_DEFAULT_REGION`, and `IAIConfig`.
- **Quality/Risk:** Helper behavior and request shape are tested. Error classification relies on message substrings, there is no region/model validation, `int` to `int32` conversion can overflow, and all providers still receive the prompt verbatim.

### `pkg/ai/amazonbedrockconverse_mock_test.go`
- **Role:** Exercises Converse configuration, request parameter selection, response extraction, error translation, and backend naming.
- **Implementation:** An injected mock records the last `ConverseInput`; tests cover nil/empty/mixed output, Claude versus non-Claude sampling controls, region override, and generic errors.
- **Dependencies:** AWS Converse types and testify.
- **Quality/Risk:** Broad deterministic unit coverage; it does not test SDK configuration/credentials, cancellation, stop-sequence serialization details, integer bounds, or the exact request prompt/role assertions.

### `pkg/ai/amazonsagemaker.go`
- **Role:** Invokes a SageMaker endpoint using a chat-style JSON schema.
- **Implementation:** `Configure` creates an AWS SDK v1 session with `session.Must`; `GetCompletion` ignores its context, sends `DEFAULT_PROMPT` plus the user prompt, accepts the EULA via custom attributes, and requires exactly one generation.
- **Dependencies:** AWS SDK v1 session and SageMaker Runtime.
- **Quality/Risk:** No assigned tests. `session.Must` can panic, cancellation/deadlines are discarded, `model` is configured but unused, the literal system prompt may be accidental, and the bespoke response contract is rigid.

### `pkg/ai/anthropic.go`
- **Role:** Implements Anthropic Messages API support, including compatible custom base URLs and custom headers.
- **Implementation:** Disables SDK environment defaults, applies explicit API key/base URL/proxy/headers, supplies model/token defaults, chooses temperature or top-p, and joins all text response blocks.
- **Dependencies:** Official Anthropic Go SDK, `net/http`, `net/url`, and `IAIConfig`.
- **Quality/Risk:** Strong HTTP-level tests cover parameters and structured errors. Proxy configuration replaces the transport and does not explicitly inherit environment proxy behavior; configured token and headers remain in mutable client state, amplified by global instance reuse.

### `pkg/ai/anthropic_test.go`
- **Role:** Verifies Anthropic HTTP request construction, defaults, base URL normalization, custom headers, response mapping, and API errors.
- **Implementation:** Uses `httptest.Server` and a complete mock `IAIConfig` to inspect Messages JSON and headers for temperature/top-p variants.
- **Dependencies:** Standard HTTP test server, JSON decoder, testify.
- **Quality/Risk:** High-value integration-style unit coverage; missing cases include invalid proxy URLs, multi-value duplicate headers, empty/non-text success responses, cancellation, and connection reuse/close behavior.

### `pkg/ai/azureopenai.go`
- **Role:** Implements Azure OpenAI chat completion with deployment mapping, Azure API modes, organization, proxy, and headers.
- **Implementation:** Builds `go-openai` Azure config, maps all models to `engine` when set, optionally wraps a transport to add headers, then returns the first chat choice.
- **Dependencies:** `sashabaranov/go-openai`, `net/http`, `net/url`, and `IAIConfig`.
- **Quality/Risk:** HTTP tests cover most configuration features. Custom headers take precedence over an explicit proxy, the custom round tripper mutates the request rather than cloning it, and an empty successful `choices` array panics.

### `pkg/ai/azureopenai_test.go`
- **Role:** Tests Azure header injection, API type/version, deployment paths, organization configuration, and completion responses.
- **Implementation:** Uses an `IAIConfig` stub and `httptest.Server` to inspect query parameters, paths, and multi-valued headers.
- **Dependencies:** Standard HTTP test server and testify.
- **Quality/Risk:** Good request-surface coverage, but it does not test empty choices, proxy/header precedence, invalid API type handling, transport request mutation, or error responses.

### `pkg/ai/bedrock_interfaces.go`
- **Role:** Defines injectable subsets of AWS Bedrock management and runtime clients.
- **Implementation:** Exposes `GetInferenceProfile` and `InvokeModel` method contracts matching AWS SDK v2 signatures.
- **Dependencies:** AWS Bedrock SDK v2 packages and `context`.
- **Quality/Risk:** Small, effective test seam; it does not include Converse, which defines a separate private interface, leaving inconsistent naming and placement.

### `pkg/ai/bedrock_support/completions.go`
- **Role:** Serializes prompts and sampling settings for Anthropic legacy/messages, AI21, Titan, and Nova Bedrock payloads.
- **Implementation:** Each adapter creates a map and JSON-marshals it; `AmazonCompletion` selects Nova by substring and otherwise Titan-style format.
- **Dependencies:** Standard JSON/context/strings and `BedrockModelConfig`.
- **Quality/Risk:** Most payload variants are tested. Context is accepted but unused, model-family routing by `strings.Contains("nova")` is brittle, and the type names `Cohere*` actually represent Anthropic schemas, harming maintainability.

### `pkg/ai/bedrock_support/completions_test.go`
- **Role:** Verifies serialized legacy Anthropic, AI21, Titan, and Nova request fields plus model support matching.
- **Implementation:** Unmarshals generated JSON into generic maps and asserts values and nested message structure.
- **Dependencies:** Standard JSON/testing and testify.
- **Quality/Risk:** Covers core serialization and routing, but omits `CohereMessagesCompletion`, nil receiver/empty model rejection, case-insensitive support, and malformed/extreme configuration values.

### `pkg/ai/bedrock_support/model.go`
- **Role:** Defines the Bedrock model configuration and composition of completion/response adapters.
- **Implementation:** `BedrockModel` groups display/name identity, an `ICompletion`, an `IResponse`, and mutable sampling configuration.
- **Dependencies:** Local completion and response interfaces.
- **Quality/Risk:** Simple contract, but interface fields can be nil and configuration is mutated per call by the parent client, so shared instances are not concurrency-safe.

### `pkg/ai/bedrock_support/model_test.go`
- **Role:** Checks model/config field construction and demonstrates completion/response interface substitutability.
- **Implementation:** Instantiates structs with lightweight mocks and asserts equality.
- **Dependencies:** `context` and testify.
- **Quality/Risk:** Basic structural coverage only; it does not exercise nil adapters, mutation/copy semantics, or concurrent access.

### `pkg/ai/bedrock_support/responses.go`
- **Role:** Parses Anthropic, AI21, Titan, and Nova Bedrock JSON responses into text.
- **Implementation:** Uses per-schema local structs; Anthropic messages concatenate text blocks, Nova returns the first content block, while AI21 and Titan directly index their result arrays.
- **Dependencies:** Standard JSON package.
- **Quality/Risk:** Valid JSON with empty `completions` or `results` panics in `AI21Response`/`AmazonResponse`; Nova silently returns empty text. This inconsistent malformed-success handling is not covered by tests.

### `pkg/ai/bedrock_support/responses_test.go`
- **Role:** Tests response parsing for legacy Anthropic, AI21, Titan, and Nova.
- **Implementation:** Supplies valid and syntactically invalid JSON and checks returned text/errors; Nova also covers empty content.
- **Dependencies:** Standard testing and testify.
- **Quality/Risk:** Useful syntax coverage, but no `CohereMessagesResponse` test and no valid-but-empty AI21/Titan cases that expose their index panics.

### `pkg/ai/bedrockmantle.go`
- **Role:** Implements AWS Bedrock Mantle through its OpenAI-compatible endpoint.
- **Implementation:** Requires region and `AWS_BEARER_TOKEN_BEDROCK`, derives the regional URL unless overridden, installs proxy/custom-header transport, and submits a standard chat request.
- **Dependencies:** `go-openai`, environment variables, shared `getRegion` and `OpenAIHeaderTransport`.
- **Quality/Risk:** Configuration and HTTP success/error have tests. It uses fixed `maxToken` instead of `IAIConfig.MaxTokens`, directly indexes choices, and storing auth-dependent mutable state in the global registry creates race/cross-request risk.

### `pkg/ai/bedrockmantle_test.go`
- **Role:** Verifies required region/token, environment region override, custom URL, completion success/error, and name.
- **Implementation:** Sets environment variables and uses an HTTP test server with OpenAI-shaped JSON.
- **Dependencies:** Standard HTTP/JSON testing and testify.
- **Quality/Risk:** Solid principal-path coverage; missing assertions include derived URL, authorization/custom headers, proxy behavior, request parameters, and empty choices.

### `pkg/ai/cohere.go`
- **Role:** Implements Cohere Chat completion.
- **Implementation:** Creates a Cohere client from token and optional base URL, sends the prompt as `Message`, sets sampling/max token values, and returns `response.Text`.
- **Dependencies:** Cohere Go v2 API/client/option packages.
- **Quality/Risk:** No assigned tests. It hard-codes `K=0`, empty preamble, and `RawPrompting=false`; validation/defaults, proxy/custom headers, empty responses, and error/cancellation behavior are unverified.

### `pkg/ai/customrest.go`
- **Role:** Adapts the analysis prompt to a bespoke REST request/response contract.
- **Implementation:** Parses an analysis-generated JSON envelope, separates full prompt from message/language options, posts bearer-authenticated JSON to the configured URL, and decodes a single response object.
- **Dependencies:** Standard HTTP/JSON/URL packages, Ollama-derived default URL/model constants, and `IAIConfig`.
- **Quality/Risk:** No assigned tests. It rejects arbitrary plain prompts, asks for NDJSON but parses one JSON object, includes the entire error body in returned errors, has no custom-header support, and defaults to the Ollama root URL despite using a different protocol.

### `pkg/ai/factory.go`
- **Role:** Wraps AI construction and Viper unmarshalling behind replaceable interfaces.
- **Implementation:** Package-global default and test factory/config-provider variables are selected by getters and reset through setters.
- **Dependencies:** Viper and the `IAI` registry.
- **Quality/Risk:** No assigned tests use these seams in this scope, and unsynchronized package-global test overrides can race or leak between parallel tests. Production `DefaultAIClientFactory` inherits `NewClient`'s shared-instance/fallback behavior.

### `pkg/ai/googlegenai.go`
- **Role:** Implements Google Generative AI completion using API-key or credentials-JSON authentication.
- **Implementation:** Detects JSON credentials by the first token byte, creates a Google client, configures a generative model per request, handles safety-blocked/no-candidate responses, concatenates text parts, and appends citations.
- **Dependencies:** Google Generative AI SDK/API option package and terminal `color` logging.
- **Quality/Risk:** Authentication setup has narrow tests; generation is untested. Citation URI is dereferenced without a nil guard, non-text response parts only print a warning, and `Close` assumes a configured nonnil client.

### `pkg/ai/googlegenai_test.go`
- **Role:** Tests empty password, API key, and malformed credential JSON configuration.
- **Implementation:** Asserts no panic for empty credentials, successful client construction for a dummy key, and error for invalid JSON.
- **Dependencies:** Testify require.
- **Quality/Risk:** Covers a prior constructor edge, but does not test request parameters, response/safety/citations, cancellation, custom endpoints, or nil-safe close.

### `pkg/ai/googlevertexai.go`
- **Role:** Implements Vertex AI Gemini completion and fixed model/region fallback policy.
- **Implementation:** Uses application-default credentials with project/region, normalizes unknown model/region to defaults, configures a model per call, and formats candidates and citations.
- **Dependencies:** Vertex AI Go SDK and terminal `color` logging.
- **Quality/Risk:** Only normalization helpers are tested. Silently replacing unknown models/regions can hide configuration mistakes; generation, credentials, nil citation fields, and close-before-configure are untested.

### `pkg/ai/googlevertexai_test.go`
- **Role:** Verifies supported and unknown model/region normalization.
- **Implementation:** Table-driven tests assert known values survive and unknown/empty values use constants.
- **Dependencies:** Testify assert.
- **Quality/Risk:** Clear helper coverage but no client construction or request/response tests, so credential and generation paths remain external-only.

### `pkg/ai/groq.go`
- **Role:** Implements Groq's OpenAI-compatible chat endpoint.
- **Implementation:** Builds `go-openai` config with Groq/default custom URL, proxy and custom-header transport, submits one user message with fixed token/penalty settings, and returns the first choice.
- **Dependencies:** `go-openai`, shared `OpenAIHeaderTransport`, and `IAIConfig`.
- **Quality/Risk:** No assigned tests. Empty choices panic, `IAIConfig.MaxTokens` is ignored, and duplicated OpenAI-compatible logic increases drift; the prompt is transmitted verbatim to the selected endpoint.

### `pkg/ai/huggingface.go`
- **Role:** Implements Hugging Face conversational inference.
- **Implementation:** Creates an inference client with token, caps configured max tokens at 500, sends prompt and sampling controls, waits for model readiness, and returns generated text.
- **Dependencies:** `go-huggingface` and Kubernetes pointer helpers.
- **Quality/Risk:** No assigned tests. Negative/zero token and sampling values are not validated, base URL/proxy/custom headers are unsupported, and the hard 500 cap is silent and provider-specific.

### `pkg/ai/iai.go`
- **Role:** Defines the common AI/config contracts, provider configuration schema, registry, backend list, and password policy.
- **Implementation:** `NewClient` scans package-global concrete client pointers and returns the matching pointer; unknown providers silently return a new OpenAI client. `AIProvider` is the getter-backed shared configuration DTO.
- **Dependencies:** Every provider implementation and `net/http` headers.
- **Quality/Risk:** High risk: stateful registered providers reuse mutable singleton clients across calls, enabling configuration races, cross-analysis state bleed, and close/reuse problems; the stateless `NoOpAIClient` is exempt. Unknown configured names can silently route prompts through OpenAI rather than fail closed; `NeedPassword` is a manually synchronized string list.

### `pkg/ai/iai_test.go`
- **Role:** Tests the Azure API-version getter.
- **Implementation:** Constructs one `AIProvider` and compares the getter result.
- **Dependencies:** Standard testing.
- **Quality/Risk:** Extremely narrow coverage; registry uniqueness, backend/factory behavior, unknown-provider fallback, all other getters, and password policy are not covered here.

### `pkg/ai/interactive/interactive.go`
- **Role:** Runs an interactive follow-up loop over an existing analysis context window.
- **Implementation:** Concatenates a fixed context prefix, raw context bytes, and user query, calls the configured AI client, and signals running/exited states over a channel.
- **Dependencies:** `analysis.Analysis`, PTerm input/output, and terminal color.
- **Quality/Risk:** No assigned tests. `strings.Contains(query, "exit")` exits on words such as “exiting,” the loop continues after sending `E_EXITED`, channel sends can block, and the context window is sent verbatim without the `GetAIResults` masking boundary.

### `pkg/ai/litellm.go`
- **Role:** Implements an OpenAI-compatible LiteLLM proxy backend.
- **Implementation:** Uses localhost:4000/v1 by default, supports token/base URL/proxy/custom headers, submits fixed-shape chat requests, and explicitly rejects empty choices.
- **Dependencies:** `go-openai`, shared `OpenAIHeaderTransport`, and `IAIConfig`.
- **Quality/Risk:** Tests cover registry/default/HTTP/no-choice behavior. It ignores configured max tokens and stop sequences, permits plaintext HTTP by default, and duplicates Groq/OpenAI/Mantle logic.

### `pkg/ai/litellm_test.go`
- **Role:** Verifies LiteLLM naming, registration/passwordlessness, default construction, request path/authentication, completion mapping, and empty-choice errors.
- **Implementation:** Uses a full config stub and HTTP servers returning OpenAI-shaped payloads.
- **Dependencies:** Standard HTTP/JSON testing and testify.
- **Quality/Risk:** Good backend-specific coverage; it does not assert sampling parameters, custom headers, proxy behavior, API errors, cancellation, or the shared registry's object identity.

### `pkg/ai/localai.go`
- **Role:** Rebrands the OpenAI-compatible client as the passwordless `localai` backend.
- **Implementation:** Embeds `OpenAIClient` and overrides only `GetName`.
- **Dependencies:** All `OpenAIClient` behavior and configuration.
- **Quality/Risk:** No assigned tests. Defaults still come from OpenAI unless callers provide a local base URL, so a missing base URL on a supposedly local backend can transmit prompts externally.

### `pkg/ai/noopai.go`
- **Role:** Supplies a deterministic no-operation AI backend for tests and dry behavior.
- **Implementation:** Accepts any config and echoes the full prompt with a fixed prefix.
- **Dependencies:** Only `context` and the local `nopCloser`.
- **Quality/Risk:** No direct assigned tests; analysis tests exercise it indirectly. Echoing the prompt means output/log consumers still see all input data, so it is not a sanitizing stub.

### `pkg/ai/ocigenai.go`
- **Role:** Implements OCI Generative AI for Cohere and Meta model families and on-demand/dedicated serving.
- **Implementation:** Uses default OCI config, looks up model metadata during configuration, builds vendor-specific chat requests, maps base versus dedicated model IDs, and extracts typed responses.
- **Dependencies:** OCI common, management, and inference SDKs.
- **Quality/Risk:** No assigned tests. `GetCompletion` repeats the same error check, context is ignored during model lookup, Cohere text and Meta text pointers are dereferenced without nil checks, and `reflect.TypeOf(nil).Name()` panics for a nil response interface.

### `pkg/ai/ollama.go`
- **Role:** Implements local/remote Ollama generation.
- **Implementation:** Defaults to localhost and `llama3`, supports an explicit proxy, sends a non-streaming generate request with temperature/top-p, and captures the callback response.
- **Dependencies:** Ollama API client, standard HTTP/URL, and `IAIConfig`.
- **Quality/Risk:** No assigned tests. It does not support auth/custom headers, callback assignment would retain only the last chunk if streaming semantics changed, and no input parameter validation is performed.

### `pkg/ai/openai.go`
- **Role:** Implements OpenAI chat completion and the shared custom-header transport used by several compatible backends.
- **Implementation:** Configures token/base URL/organization/proxy/headers, sends one user message with fixed max completion tokens and penalties, and returns the first choice; the transport clones requests before adding headers.
- **Dependencies:** `go-openai`, standard HTTP/URL, and `IAIConfig`.
- **Quality/Risk:** Header injection is tested, but empty successful choices panic and configured max tokens/stop sequences are ignored. A zero-value `OpenAIHeaderTransport.Origin` would panic, and global registry reuse makes mutable credentials/configuration unsafe under concurrency.

### `pkg/ai/openai_header_transport_test.go`
- **Role:** Verifies OpenAI custom headers, including repeated values, reach the HTTP endpoint.
- **Implementation:** Provides a complete `IAIConfig` mock, runs a local chat endpoint, and asserts request headers and successful completion.
- **Dependencies:** Standard HTTP test server and testify.
- **Quality/Risk:** Covers the main custom-header flow but not cloning/nonmutation, proxy/organization/base URL errors, authentication, request parameters, empty choices, or HTTP error mapping.

### `pkg/ai/prompts.go`
- **Role:** Defines default, Prometheus, Kyverno, and custom REST prompt templates keyed by result kind.
- **Implementation:** Templates interpolate language and joined failure text; the default asks for a 280-character error/solution, while integration templates impose specialized output formats.
- **Dependencies:** Consumed by `analysis.GetAIResults` through global mutable `PromptMap`.
- **Quality/Risk:** No tests validate formatting, placeholder counts, escaping, or prompt-injection resistance. Failure text is embedded as instructions/data with delimiter conventions only, and `raw_promt` is misspelled and bypassed by analysis's explicit JSON path.

### `pkg/ai/watsonxai.go`
- **Role:** Implements IBM watsonx text generation.
- **Implementation:** Applies default model/max tokens, requires API key/project ID, constructs the SDK client, generates text with sampling controls, and rejects empty output.
- **Dependencies:** IBM watsonx Go models SDK.
- **Quality/Risk:** No assigned tests. Error messages use test-oriented wording and `%v` rather than wrapping, `GetCompletion` does not pass its context to the SDK call, and numeric conversions to unsigned can turn negative config into very large values.

### `pkg/analysis/analysis.go`
- **Role:** Constructs analyses, orchestrates built-in/custom analyzers, invokes AI, performs declared masking/restoration, and reads/writes completion caches.
- **Implementation:** `NewAnalysis` builds Kubernetes/cache/AI clients from Viper; analyzers run under a capped semaphore; `GetAIResults` masks only values listed in each `Failure.Sensitive`, selects `PromptMap`, caches a base64 response by provider/language/joined text, and restores tokens afterward.
- **Dependencies:** Kubernetes/analyzer registries, AI/cache/custom packages, Viper, utility masking/hash/header helpers, OpenAPI discovery, progressbar, and synchronization primitives.
- **Quality/Risk:** High-value orchestration tests exist, but sanitization/cache behavior is barely asserted. Verified boundary: undeclared sensitive text is sent verbatim; masking uses the utility's unescaped regex pattern and can mis-match or panic. Cache identity omits model, endpoint, parameters, and prompt template, so semantically different requests can reuse a response. Custom clients are never closed and use a stricter namespace precheck than built-ins.

### `pkg/analysis/analysis_test.go`
- **Role:** Tests filter selection, namespace checks, outputs, AI/cache basics, verbose logging, concurrency guards, and custom-analyzer nil/populated results.
- **Implementation:** Uses fake Kubernetes clients, gomonkey patches, no-op AI/cache instances, Viper globals, and local gRPC servers.
- **Dependencies:** Kubernetes fake client/testing APIs, gRPC schema/server, Viper, utility capture helpers, gomonkey, and testify.
- **Quality/Risk:** Broad regression coverage for orchestration, but global Viper state is inconsistently reset and could make tests order-sensitive. It does not assert actual masking/restoration, cache hits/keys/corruption/store errors, AI quota mapping, cancellation, stats races/order, max cap, client closure, or custom RPC failures/timeouts.

### `pkg/analysis/output.go`
- **Role:** Renders analysis results and statistics as JSON or terminal text.
- **Implementation:** Counts failures to derive status, marshals `JsonOutput`, or emits colored provider/warning/result/error/doc/detail lines; format functions live in a map.
- **Dependencies:** Standard JSON/formatting/strings and terminal `color`.
- **Quality/Risk:** Basic format selection is tested. JSON exposes full `Failure` exported fields (default names, including `Sensitive` mappings) because they have no JSON tags, potentially disclosing both masked and unmasked values; text intentionally prints raw failure/details.

### `pkg/analysis/output_test.go`
- **Role:** Tests empty JSON/text outputs and unsupported format rejection.
- **Implementation:** Table-driven assertions compare or contain expected strings.
- **Dependencies:** Testify require.
- **Quality/Risk:** Minimal happy-path coverage; no populated results, warnings, provider, sensitive-field serialization, stats, color behavior, deterministic format-list order, or marshal failure cases are tested.

### `pkg/cache/azuresa_based.go`
- **Role:** Implements Azure Blob Storage cache operations.
- **Implementation:** Uses default Azure credentials, creates the configured container, and implements upload/download/list/delete/existence via the blob SDK.
- **Dependencies:** Azure Identity and Blob SDKs, background context, and logging.
- **Quality/Risk:** No assigned tests. `Configure` calls `log.Fatal` for missing settings and credential/client construction failures, terminating the process instead of returning an error; all operations use uncancellable background context, and existence scans every blob rather than fetching properties for one key.

### `pkg/cache/cache.go`
- **Role:** Defines the cache interface, cache registry/factory, Viper persistence, and remote-cache construction.
- **Implementation:** `New` returns the matching package-global cache pointer for recognized names and a fresh `&FileBasedCache{}` for unknown names; `GetCacheConfiguration` creates fresh concrete instances, configures them, and defaults to file storage.
- **Dependencies:** All cache implementations, Viper, and gRPC status codes.
- **Quality/Risk:** Factory/config tests cover core choices. Registry instances returned by `New` for recognized names retain mutable disable/session/config state across callers and are race-prone; unknown types receive a fresh file cache, while `NewCacheProvider` rejects them, creating inconsistent APIs.

### `pkg/cache/cache_test.go`
- **Role:** Tests cache type selection, Interplex provider creation, invalid type rejection, and Viper add/get/remove persistence.
- **Implementation:** Uses a temporary Viper config and lightweight Interplex configuration.
- **Dependencies:** Viper, filesystem temp files, and testify.
- **Quality/Risk:** Covers routing/persistence but not global instance identity/state leakage, parse/write errors, cloud configuration, disabled behavior, or fallback warning semantics; formatting is non-gofmt style.

### `pkg/cache/file_based.go`
- **Role:** Implements the default XDG filesystem completion cache.
- **Implementation:** Resolves `k8sgpt/<key>`, writes mode 0600, and supports read/list/remove/existence; existence errors are warnings and become `false`.
- **Dependencies:** `adrg/xdg`, filesystem APIs, and `util.FileExists`.
- **Quality/Risk:** CRUD and path shape are tested. Keys are trusted path fragments at this layer, listing assumes only files, directory permissions are delegated to XDG, and cache content is merely base64 upstream rather than encrypted.

### `pkg/cache/file_based_test.go`
- **Role:** Verifies file cache configuration, name/disable flag, CRUD/list behavior, and XDG path layout.
- **Implementation:** Temporarily changes `XDG_CACHE_HOME`, creates data, and cleans the directory afterward.
- **Dependencies:** XDG helper, filesystem APIs, and testify.
- **Quality/Risk:** Good isolated happy-path coverage, but it mutates process environment manually rather than `t.Setenv`; no permissions, invalid/traversal keys, missing files, directories, I/O errors, or concurrent access are tested.

### `pkg/cache/gcs_based.go`
- **Role:** Implements Google Cloud Storage cache operations and bucket creation.
- **Implementation:** Uses application-default credentials, validates bucket/project/region, creates a missing bucket, and performs object CRUD/list/existence with a background context.
- **Dependencies:** Google Cloud Storage SDK and iterator API.
- **Quality/Risk:** No assigned tests. Missing config and client-construction errors call `log.Fatal`; non-`ErrBucketNotExist` attribute errors are ignored and configuration still succeeds, client resources are never closed, and operations cannot be canceled.

### `pkg/cache/interplex_based.go`
- **Role:** Implements a remote Interplex gRPC cache.
- **Implementation:** Opens a new insecure connection for each store/load/remove, optionally rewrites the endpoint in local mode, maps CRUD RPCs, implements `Exists` through `Load`, and leaves `List` as an empty success.
- **Dependencies:** Generated Interplex schema clients, gRPC, environment variables, and background contexts.
- **Quality/Risk:** Store/load and client-construction regression tests exist. Plaintext transport, no authentication, and background-context RPCs with no deadlines let an unresponsive server block calls indefinitely; returning empty success for unsupported `List` is ambiguous, and per-call connections add overhead.

### `pkg/cache/interplex_based_test.go`
- **Role:** Tests Interplex store/load/exists and verifies invalid connection strings return errors rather than panic.
- **Implementation:** Starts a gRPC server on fixed port 50051 and provides in-memory Set/Get handlers.
- **Dependencies:** Generated Interplex server/client schemas, gRPC, networking, and standard testing.
- **Quality/Risk:** Valuable nil-connection regression coverage, but the server is never stopped, fixed port use can collide, startup is racy, delete/list/disable/local-mode are untested, and absent RPC deadlines mean failures can hang.

### `pkg/cache/s3_based.go`
- **Role:** Implements S3-compatible completion caching and optional bucket creation.
- **Implementation:** Creates an AWS SDK v1 session, optionally installs a path-style custom endpoint with configurable TLS verification, probes/creates the bucket, and implements object CRUD/list/head.
- **Dependencies:** AWS SDK v1 S3/session, TLS, and HTTP.
- **Quality/Risk:** No assigned tests. Any `HeadBucket` error other than recognized credential strings triggers `CreateBucket`, which can mask permission/network failures; optional `InsecureSkipVerify` weakens transport security, response close errors are ignored, and list results are not paginated beyond the SDK call's first page.

### `pkg/cache/types.go`
- **Role:** Defines the persisted union of cache-provider configurations and list metadata.
- **Implementation:** `CacheProvider` contains current type and Azure/GCS/S3/Interplex subconfigs; `CacheObjectDetails` holds name and update time.
- **Dependencies:** Concrete cache configuration types and `time`.
- **Quality/Risk:** No validation or redaction metadata exists at this layer. The union can hold conflicting populated providers, and YAML/mapstructure naming is inconsistent across the surrounding config surface.

### `pkg/common/listoptions_test.go`
- **Role:** Tests the shared analyzer's Kubernetes list selector construction.
- **Implementation:** Table-driven cases cover absent/present resource name alone and combined with a label selector.
- **Dependencies:** Kubernetes field selectors and `common.Analyzer`.
- **Quality/Risk:** Focused and complete for current behavior; it does not validate invalid label/resource input because the helper delegates encoding without returning errors.

### `pkg/common/types.go`
- **Role:** Defines analyzer input, analysis results/failures/sensitive mappings, stats, pre-analysis resource union, and catalog/extension resource shapes.
- **Implementation:** `Analyzer.ListOptions` pushes `ResourceName` into a `metadata.name` field selector; `IAnalyzer` returns `[]Result`; `Failure` carries text, optional docs, and mask mappings.
- **Dependencies:** AI/Kubernetes clients, Kubernetes APIs, OpenAPI, KEDA, Kyverno, and Gateway API types.
- **Quality/Risk:** Central contracts are broad and tightly coupled to many integrations. `Failure`/`Sensitive` lack JSON tags or redaction controls, so JSON output includes `Unmasked` secrets; `Analyzer` also exposes mutable results/pre-analysis fields that are unused by the orchestrator shown here.

### `pkg/custom/client.go`
- **Role:** Connects to an external custom analyzer and maps its protobuf result into `common.Result`.
- **Implementation:** Dials `<url>:<port>` with insecure gRPC, sends an empty background-context `RunRequest`, maps scalar fields/errors, and intentionally drops schema-sensitive metadata.
- **Dependencies:** Generated K8sGPT custom-analyzer schema, gRPC, and common result types.
- **Quality/Risk:** High risk: no TLS/authentication or deadline, the retained `ClientConn` has no `Close` method and is leaked by each analysis run, and a nil `RunResponse` would panic. Dropping sensitive mappings means later AI anonymization cannot protect custom failure text.

### `pkg/custom/client_test.go`
- **Role:** Tests mapping a populated custom-analyzer response into common result fields.
- **Implementation:** Injects a mock generated client and asserts name/kind/details/parent plus empty errors.
- **Dependencies:** Generated schema, gRPC call options, and testify.
- **Quality/Risk:** Very narrow coverage: error-detail mapping, nil result/response, RPC errors, context/deadlines, connection lifecycle, and sensitive-data loss are untested; formatting is non-gofmt style.

### `pkg/custom/types.go`
- **Role:** Defines JSON configuration for custom analyzer name and network connection.
- **Implementation:** Stores URL and port as strings inside `CustomAnalyzer`.
- **Dependencies:** Consumed by Viper unmarshalling and `custom.NewClient`.
- **Quality/Risk:** No validation methods or tests; port is a string here but an integer in `pkg/custom_analyzer`, creating duplicate, inconsistent public configuration contracts.

### `pkg/custom_analyzer/customAnalyzer.go`
- **Role:** Validates new custom-analyzer names and uniqueness of name/connection.
- **Implementation:** Enforces an RFC-1123-like lowercase DNS regex, rejects duplicate names, and uses `reflect.DeepEqual` to reject exact URL/port duplicates.
- **Dependencies:** Standard regexp/reflect/formatting.
- **Quality/Risk:** No assigned tests. URL emptiness/syntax, port range, canonical host equivalence, TLS requirements, and reachability are not validated; error strings are capitalized/inconsistent, and this config type diverges from `pkg/custom/types.go`.

## Scope Findings

- **High - Unknown provider names can fail open to external OpenAI:** `pkg/ai/iai.go` returns `&OpenAIClient{}` for every unknown name, while `pkg/analysis/analysis.go` accepts any configured provider name before calling that factory. A typo or extension name with no base URL can therefore send Kubernetes failure prompts to OpenAI rather than reject configuration. This is verified source behavior; actual exposure depends on the supplied credentials/configuration.
- **High - Stateful registered AI clients are shared mutable singletons:** `pkg/ai/iai.go` stores concrete pointers in global `clients` and returns them directly. The stateful clients' `Configure` methods mutate credentials, model, endpoint, or SDK state, so concurrent or sequential analyses can overwrite each other, race, close a client used elsewhere, or route a prompt with another caller's configuration. `NoOpAIClient` is stateless and therefore exempt from this finding.
- **High - Anonymization can fail and JSON output preserves unmasked mappings:** `pkg/analysis/analysis.go` masks only declared `Failure.Sensitive` values and calls a utility replacement that compiles `Unmasked` as an unescaped regular expression; regex metacharacters can produce incorrect replacement or a panic. `pkg/common/types.go` leaves `Sensitive.Unmasked` exported without JSON tags, and `pkg/analysis/output.go` marshals results directly, so JSON includes the original values even when prompt anonymization is requested.
- **High - Cloud cache configuration can terminate the entire process:** `pkg/cache/azuresa_based.go` and `pkg/cache/gcs_based.go` call `log.Fatal` for missing fields and SDK credential/client construction failures instead of returning errors through `ICache.Configure`. This bypasses caller recovery, cleanup, and structured error reporting.
- **High - Custom analyzer transport is unauthenticated, unbounded, and leaked:** `pkg/custom/client.go` uses insecure gRPC, `context.Background()` without a deadline, and exposes no connection close; `pkg/analysis/analysis.go` creates one client per custom analyzer run without closing it. The response mapper also drops sensitive metadata, so custom failure text cannot participate in the normal masking contract.
- **Medium - Cache identity is insufficient for request semantics:** `pkg/analysis/analysis.go` keys only provider name, language, and joined failure text. Model, endpoint, sampling parameters, and prompt template/kind are omitted, allowing stale or semantically wrong completions to be reused. Base64 is encoding, not confidentiality; non-anonymized responses stored by `pkg/cache/file_based.go` or remote backends may contain cluster identifiers.
- **Medium - Several successful but empty provider responses panic:** `pkg/ai/openai.go`, `pkg/ai/azureopenai.go`, `pkg/ai/groq.go`, and `pkg/ai/bedrockmantle.go` index `Choices[0]`; `pkg/ai/bedrock_support/responses.go` indexes AI21 `Completions[0]` and Titan `Results[0]`; `pkg/ai/ocigenai.go` dereferences response text pointers. LiteLLM and Bedrock Converse show the preferable explicit error pattern.
- **Medium - Interactive mode bypasses analysis sanitization:** `pkg/ai/interactive/interactive.go` sends the raw context window and query directly to `AIClient.GetCompletion`; it does not use `GetAIResults` or its `Failure.Sensitive` masking. Whether the supplied context contains sensitive data is caller-dependent, but the bypass is verified.
- **Medium - Cache factories and remote transports have inconsistent safety:** `pkg/cache/cache.go` returns global mutable registry instances from `New` for recognized cache names, while unknown names receive a fresh file cache; `pkg/cache/interplex_based.go` uses plaintext gRPC with no deadline and reports unsupported `List` as empty success; `pkg/cache/s3_based.go` optionally disables TLS verification and treats most `HeadBucket` failures as a reason to create the bucket.
- **Low - Provider surface is behaviorally inconsistent and under-tested:** `pkg/ai/amazonsagemaker.go` and `pkg/ai/watsonxai.go` ignore request context, several OpenAI-compatible backends ignore configured max tokens, and model/region validation ranges from strict error to silent fallback. Cohere, Custom REST, Groq, Hugging Face, OCI, Ollama, SageMaker, Watsonx, Azure/GCS/S3 caches, interactive mode, and custom-analyzer validation have no direct assigned unit tests.
