The terminal is an authenticated client of the orchestrator. `Run` requires an
explicit human bearer token, independent scope, input and output; starting an
unattended agent must not call it. The caller keeps the enrolled agent token out
of this configuration. Redirects are rejected to prevent forwarding human tokens.

The terminal polls durable questions, action state, notification state and
incident diagnostic jobs. Commands are explicit:

- `answer REQUEST CODE` submits the displayed question's version and one allowed
  diagnostic context code.
- `approve ACTION HASH` sends the displayed exact hash to the existing action
  approval API. Generic chat replies do not authorize mutations.
- `reject ACTION` calls the existing cancellation API.
- `ack NOTIFICATION` acknowledges delivery through the notification service.
- `quit` or EOF detaches, leaving unanswered requests pending.

Clarification uses a closed vocabulary, so neither arbitrary provider prose nor
logs or sensitive operator notes enter this store. New question types require a
reviewed vocabulary addition in the model, migration and UI. Diagnostic job
completion can create a question in its fenced result transaction. Answers use a
scoped conditional update on ID/version/status/expiry and persist the verified
human identity with an outbox audit event. Expiry checks use PostgreSQL's actual
wall clock after obtaining the application lock.

Slack incoming webhook destinations use the same durable outbox/retry/escalation
service. `delivery.NewHTTPSender(publicURL)` renders native Slack blocks pointing
to the scoped authenticated UI. No Slack workspace/user mapping is configured in
this version, so Slack replies and unsigned callbacks have no approval authority.
