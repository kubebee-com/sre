# Authenticated inbound commands

`New(configs, execute)` serves `POST /channels/{id}/events`. It invokes the supplied governed service callback only after authenticating the platform request, matching the configured account and conversation, and resolving a configured external user to a principal. Platform names, display names, roles, and message-provided groups never grant authority. Configured principal IDs and groups must match the authorization policy used by the service.

Supported transports:

| Provider | Authentication | AccountID | ConversationID | Input |
| --- | --- | --- | --- | --- |
| Slack | HMAC SHA-256 signing secret from SecretEnv | Workspace/team ID | Channel ID | `/sre ack notification-id` slash command |
| Discord | Hex Ed25519 PublicKey from application configuration | Guild/server ID | Channel ID | `/sre` application command with one required STRING option named `command` |
| Telegram | Unique webhook secret from SecretEnv | Bot username, without `@` | Numeric chat ID, including minus sign for groups | `/sre ack notification-id` or `/sre@bot_username ack incident-id` |

The Discord application public key authenticates the application; the guild and channel are checked separately. Telegram updates do not contain the receiving bot identity: each configured endpoint must have its own unique webhook secret, set using the Bot API `setWebhook` secret_token parameter. Use separate bots if separate endpoints are needed. These secrets are distinct from outbound bot access tokens. Configure TLS termination and a publicly reachable HTTPS URL for the provider webhook.

Commands contain only the following tokens:

- `approve ACTION_ID PLAN_HASH`: exactly 64 lowercase hexadecimal hash characters.
- `reject ACTION_ID`
- `answer QUESTION_ID VERSION OPTION_CODE`: positive canonical decimal version and an existing option code.
- `ack NOTIFICATION_ID`

The adapter does not start investigations, diagnose incidents, run tools, or execute arbitrary text. The service remains responsible for policy, scope, separation of duties, exact plan hash checks, expiry, optimistic version checks, and transition idempotency. Providers can redeliver a valid request inside the freshness window; the adapter deliberately relies on those governed transitions rather than a process-local replay cache.

Slack and Discord signature timestamps and Telegram message dates must be at most five minutes old and no more than 30 seconds in the future. Request bodies are limited to 64 KiB. Configuration permits at most 128 endpoints, 1,024 bound users per endpoint, and 128 groups per user. Telegram webhook secrets must contain 1–256 ASCII letters, digits, underscores, or hyphens. Bot messages and Telegram sender-chat identities do not invoke commands. Edited Telegram updates and unsupported interaction types are rejected. Discord signed PING receives PONG without invoking a command.

Principals have the configured `PrincipalID`, a copy of configured groups, and issuer `https://sre.internal/messaging/<provider>/<escaped-account>`. This issuer identifies the local trust mapping; it is not an OIDC discovery URL. Principals expire after five minutes. External display names cannot change the mapped identity.

Slack responses are ephemeral; Discord responses are ephemeral and disable mention parsing. Responses contain only generic acceptance/rejection, never callback error text. Telegram returns an HTTP acknowledgement without sending a chat message. Permanent policy/state errors receive a native acknowledgement to prevent retries from repeatedly attempting a denied state transition. Errors wrapping `ErrRetryable`, `context.DeadlineExceeded`, or `context.Canceled` receive a generic HTTP 503 so transient failures are not acknowledged as delivered. The callback receives a two-second deadline (or an earlier parent deadline) and must honor cancellation; the adapter does not detach state transitions into background goroutines. Acceptance only means the service callback succeeded, not that a remediation has completed.

Other messaging providers have no inbound adapter in this package. Outbound notification support elsewhere must not be interpreted as authenticated inbound control.

Authentication references:

- [Slack request verification](https://docs.slack.dev/authentication/verifying-requests-from-slack/)
- [Discord interaction signatures and responses](https://docs.discord.com/developers/interactions/receiving-and-responding)
- [Telegram webhook secret_token](https://core.telegram.org/bots/api#setwebhook)
