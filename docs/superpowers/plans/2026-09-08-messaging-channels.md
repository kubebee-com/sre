# Messaging channels implementation plan

**Goal:** Add major IM notification adapters and verified human commands while preserving shared approval policy, audit and HA delivery.

**Architecture:** Explicit typed notification channels extend the existing durable delivery routes. A separate messaging package verifies platform requests and maps configured account/conversation/user identities to principals. The orchestrator executes typed commands through existing services. Secrets remain environment references.

- [x] Add native Slack, Teams, Discord, Telegram, Google Chat, WhatsApp template and Matrix outbound adapters, with mocked HTTP contract and failure tests.
- [x] Extend delivery routes to select typed channels while preserving generic endpoint routes, retries and escalation. Test validation and dispatch selection.
- [x] Add signed Slack/Discord and secret-authenticated Telegram incoming commands with strict account/conversation/user bindings, bounded parsing and negative authentication tests.
- [x] Wire callbacks into orchestrator startup and existing approve/cancel/clarification/ack services. Restrict commands to existing versioned transitions; no arbitrary chat-triggered execution.
- [x] Document configuration, channel capability differences, provider setup and secret mounting.
- [x] Run package coverage, full Go suite, race checks and Helm tests. Review changed paths and fix issues before reporting completion.

Verification completed with disposable PostgreSQL: full Go suite, targeted race tests, go vet, both product builds and unified Helm tests passed. Incoming unit coverage 95.6%; new outbound adapter functions 100%; CI gates each at 90%. Independent review findings on response deadlines and retryable errors were fixed with regression tests. No live IM calls were made.
