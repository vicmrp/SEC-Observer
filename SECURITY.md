# Security model and reporting

Observe is a local defensive investigation prototype. Treat Windows events, model reports, and exports as potentially sensitive. It does not guarantee detection, complete capture, or comprehensive redaction.

## Trust boundaries

1. Windows logs → a fixed PowerShell reader → Node collector. User prompts are never interpolated into PowerShell commands. No collected command is executed.
2. Local browser → loopback API. A random per-run request token, Host/Origin checks, no CORS, restricted static-file routes, CSP, and escaped rendering defend against ordinary cross-site requests and stored event-field XSS.
3. Local capture → redaction and bounded evidence snapshot → explicitly selected provider. A manual preview is immutable and expires; automatic review requires separate consent.
4. Events → Astra. The prompt treats evidence as untrusted data, gives the model no tools, requires citations, and validates IDs. Prompt injection can still influence an assessment; AI output is advisory.
5. Managed client → gateway → OpenAI. Customer token hashes and server API keys must remain secret; TLS termination is an operator responsibility. The gateway persists quotas, not evidence. It is single-instance only.

Do not expose the desktop API through a public tunnel or bind it to external interfaces. Do not run an Internet-facing managed gateway as administrator. Prefer a dedicated service with minimal event-log permissions for production collection. A development instance run as administrator increases the impact of a server defect.

Local malware running as the same OS user can read the session files and API bootstrap token. An administrator can disable sensors or edit logs. The MVP cannot detect all such tampering. Logs can contain credentials even when the user did not intentionally enter them in Observe.

## Reporting a vulnerability

This local prototype has no public maintainer contact or repository yet. Before publishing a fork, replace this section with a private reporting channel and supported-version policy. Do not post raw event logs, API keys, access tokens, or personal paths in public issues.
