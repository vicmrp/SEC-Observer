# Observe for Windows — 0.9.1

Observe is a local Windows activity monitor with an optional **chatGPT observer** plugin. Source and builds live in your repository checkout.


## Harmless mod safety test (0.9.1)

Plugins → **Cities II mod observer** (disabled by default) installs a small local Cities II test mod and arms a temporary Windows ETW sensor. The mod reads only an Observe-created synthetic document outside the game. Observe records the process, read request and completion status, raises an alert, preserves the records, and can prepare an evidence-bound chat. The mod's own receipt is visibly separate from independent Windows evidence. This exercises canary detection; it is not general per-mod attribution or proof that other mods are safe. See **Harmless-Mod-Test.md** in the release or **Observe.CanaryMod/README.md** in source for the exact actions and cleanup.
## Processes

Workspace → Processes replaces the activity timeline. The Task Manager style view groups apps, background processes and Windows processes, with a process-tree switch, local executable icons, search and CPU/memory sorting. Refresh takes a still snapshot of CPU, working set, private bytes, process I/O rate, recorded flows, threads and publisher. I/O includes file and device operations; it is not a disk-only counter. Flow counts cover the last hour, not a network throughput estimate.

Click a process for command line, parent PID, user, session, priority, architecture, creation time, memory and handle counts, SHA-256, offline Authenticode verification, modules, threads and services. You can copy details, open its network activity, or attach a recording. Creation time is checked before opening details to reject reused PIDs. Access-denied values remain unavailable. This is a user-mode process inspector: kernel stacks, detailed kernel handle names and Process Explorer's full security-token tools are not implemented.

## Saved evidence and storage

Observed events are appended to daily journals in %LOCALAPPDATA%\ObserveDesktop\evidence and flushed to disk on each collector batch (normally once a second). Network, process and PowerShell history survives restarts. Old recordings and timed sessions are imported once into the journal. Known apps, watch preferences, chat history, focused recordings and the latest process display snapshot also persist. Captured process metrics are kept in the journal. UI and model limits do not delete journal records. There is no automatic journal expiration; check storage and export/delete when needed. Crashes can lose events still awaiting a flush; missing sensor events cannot be recovered from the journal.

Overview → Local log storage shows Observe's saved bytes by category. It updates on entering Overview and when you click Refresh. Export logs creates a ZIP of event journals, recordings, sessions, chats and app/process history. Keys, preferences, WebView cache, Windows event logs and sensor restoration backups are excluded. Exports contain raw evidence, including paths and script/command text.

Delete saved logs requires typing DELETE and finishing active recordings. It deletes only the categories listed in the confirmation. It does not clear Windows event logs or credentials, and observation continues afterwards. Windows-retained records can appear again after a historical query. Automated tests delete only isolated test data.

## PowerShell Flows and Activity

PowerShell uses the Network-style sidebar, period selector, search and manual Refresh. Flows lists recorded script text, ISE invocations and module activity in time order. Activity groups identical complete script text across hosts; incomplete fragments stay separate. All saved history includes journal records older than seven days, plus the latest Windows log query. Counts are observations, not a guaranteed count of executions: PowerShell can reuse a compiled script block without logging its text again.

Click either view to inspect text, timestamps, host PID, fragment completeness and original evidence. With chatGPT observer configured, Summarize & review logging opens a chat containing that selected record's evidence. Sending asks for its purpose, concerning operations, and whether to retain it or consider a narrow local-storage/future-Wazuh exclusion. Recommendations do not apply filters. Wazuh remains a future integration.

The optional PowerShell 7 channel is shown under Sensor coverage instead of appearing as a general failure. PowerShell 7 needs its own registered provider; portable copies may not register one. Windows PowerShell 5.1 and ISE use a separate channel. If you use PowerShell 7, Microsoft documents registering its provider from that installation with RegisterManifest.ps1 in an elevated PowerShell 7 session, then enabling its logging policy and opening a fresh session. Observe does not register an arbitrary bundled runtime automatically. See https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows

## Tracked apps

Open **Workspace → Tracked apps** (or **Track an app** on Overview). Known apps lists executable paths observed previously or currently running; it is not a software-installation inventory. Select a running PID to attach without relaunching. **Watch next starts** remembers the executable path, attaches to current instances and records later starts while monitoring is on. Multiple recordings can coexist. Watched/attached recordings finish when the root and observed descendants have ended. After restart, watched apps still running can start a new recording; collection gaps remain explicit. Historical entries can be watched even when they are not running.

To retain the original explicit launch workflow, browse to a local executable, optionally supply arguments, and click **Launch & record**. The recorder is armed before the process runs. Its exact PID and creation time identify the root, and SHA-256 identifies the selected executable. Apps run with the ordinary desktop user's token when Observe is elevated. If Windows cannot obtain that token, launch fails rather than escalating the app.

Recordings include a process tree, connections/DNS, local suspicious-behavior findings, and file/registry evidence when the configured sensors captured it. Process GUIDs and bounded PID lifetimes avoid assigning an unrelated later process to the run. Windows process trace and a one-second process-ancestry sampler supplement Sysmon; brief children can still be missed and sampled exit times are approximate. Children can continue after the root exits. **Finish recording** saves the session without terminating the app or its children. Closing Observe also finishes the recording.

Use **Refresh** to update the displayed recording. **Ask chatGPT observer** creates a chat bound to that exact recording; it sends no API request until Send. Every answer in a bound chat refreshes its evidence from the saved recording. Old recorded-launch chats are rebound when the matching saved recording exists. Asking about a different executable switches to a general historical lookup.

For a mod, record the game before and after installation and compare the saved sessions. A mod loaded inside the game shares the same process: Observe cannot reliably separate its behavior from game code. Work delegated to an already-running launcher, service or scheduled task can fall outside the descendant tree. Observe runs programs on your actual PC; it is not a sandbox, antivirus engine or guarantee of safety. Review signals and known indicators are leads, not a malware verdict.

Recordings are saved under `%LOCALAPPDATA%\ObserveDesktop\tracked-launches`, with a ten-second checkpoint. Focused files keep process-lifetime records and a bounded recent event view; the evidence journal retains all captured records, and opening a recording merges its relevant time window back in. Interrupted recordings are labelled on reopening. Captures contain paths and command lines and are not encrypted.

## Game performance

Click **Game performance** in the header. Observe finishes active recordings, requests Windows administrator approval if managed machine settings need changing, and restarts with its event-log watchers, TCP/DNS polling, process sampler and ETW sessions stopped. Sensor reads and new tracked launches are blocked. Saved chats and recordings remain accessible. **Restore monitoring & restart** reapplies the paused configuration and restarts collection.

Only changes covered by Observe's sensor backups are reversed. Sysmon installed by Observe is temporarily uninstalled (including its driver); an installation that existed earlier returns to its supplied original configuration. PowerShell policies and channel settings return to their saved prior values. Pre-existing monitoring can therefore remain active. Defender, firewall and unrelated security tools are not altered. Existing PowerShell hosts may cache their previous policy until reopened.

The protected `%ProgramData%\ObserveDesktop\game-performance.json` journal retains the exact registry/channel settings needed for resuming, plus the selected Observe Sysmon profile. Failed or interrupted changes keep their backup and show an incomplete-transition notice. Use Restore monitoring to retry. Monitoring gaps cannot be recovered. Close older Observe instances before using this mode; older releases do not honor the pause state. Automated tests validate the restoration plan and a paused startup without changing machine logging or uninstalling Sysmon.

## Network Flows and Activity

Network opens a frozen snapshot with a Flows / Activity switch, period and app filters, search, summaries, pagination and an observed-transfer chart. **Refresh snapshot** updates the view; background state pushes do not replace its rows. Clicking an app narrows its flows. Activity groups by application path and shows participating PIDs, destinations and observed transfer bytes. A blank byte value means unavailable; the chart does not render missing measurements as zero traffic.

Network reads the persistent evidence journal. A snapshot shows up to 1,000 grouped flows in its chosen period; this display limit does not delete saved records. Activity from before collection or during game performance mode can be unavailable. Separate sources can report the same connection. Bytes are measured ETW transfers, not router billing totals. DNS cache names are tentative candidates; machine-wide cache records are not assigned to an app.

Icons come from local executable resources, with initials as a fallback. No remote logo requests are made. Countries are unknown by default. **Import country map** accepts a local CSV with columns `CIDR,country` (ISO two-letter code), up to 4 MB / 50,000 IPv4 or IPv6 prefixes. The longest matching prefix is used. Private/reserved addresses are marked local and never assigned a country. Common country flags are drawn locally; other countries show their code. No country database or external geolocation query is bundled.

## ThreatFox plugin

ThreatFox is optional and disabled by default. Configure an **Auth-Key** in Plugins; the key is protected with Windows DPAPI. Click **Check** beside a public destination, **Check hash** in a recording, or use the plugin's indicator form. This sends the selected IP, domain or SHA-256 to the fixed ThreatFox API endpoint. There are no automatic lookups, file uploads or IOC submissions. Results are cached in memory for 30 minutes; removing the plugin clears its key and cache. Game performance mode blocks lookups.

Results include malware labels, confidence and first/last-seen fields. A match needs investigation; no match does not establish safety. The community API expires indicators older than six months. API behavior and authentication were checked on 2026-09-19 against the [official ThreatFox API documentation](https://threatfox.abuse.ch/api/). Get a key through the [abuse.ch authentication portal](https://auth.abuse.ch/).

## chatGPT observer

1. Open **Workspace → chatGPT observer**, then **Set up plugin**, or configure it from **Plugins**.
2. Enter your OpenAI API key and choose a model: GPT-5 nano, GPT-5.6 Luna, Terra, Sol, or GPT-6 Astra. Luna is the default for new setups; saved choices are preserved. You can also change the model from the chat header. Availability depends on your OpenAI project.
3. Ask, for example: `I just opened "C:\Games\Example\Game.exe". Please tell me what this program did to my computer.`
4. Read the streamed answer, open its evidence citations, and expand the evidence snapshot to inspect exactly which records were shared.
5. Continue the conversation. Follow-ups reuse its latest nonempty snapshot. Empty snapshots are searched again automatically. Check **Refresh evidence**, change the evidence period, or name a different program to gather new records.

Chat history appears on the left. You can create, search, rename, reopen and delete conversations. Enter sends; Shift+Enter adds a line. Stop cancels a pending request. Failed requests retain any generated text, the message and evidence. An error or Stop notice is appended below the answer; it never replaces generated text. Copy copies the answer; View error log and Copy error log retain separate diagnostics. Partial output is checkpointed at most every 500 ms during streaming (the first chunk is saved immediately), then saved again when the request ends. An abruptly closed app can lose text since its latest checkpoint.

Failed answers explain the provider's reason when available. **View error log** opens diagnostics with **Copy error log**: HTTP status, error code, request/response IDs, model, stage, and request budgets. Keys are redacted; request bodies and raw evidence are not copied into diagnostics. Old errors from 0.6 did not retain provider details; retry in 0.7.2 to record them. Earlier versions discarded generated text when a request failed; this update cannot recover that discarded text. Local citation failures identify the local check and retain a bounded, redacted list of unmatched references in the log.

The former Overview investigation form, Investigation results and Investigations pages, their commands, and the old session-only API-key settings have been removed from the default Windows dashboard. The script-correlation code remains as a shared evidence utility. Existing saved investigations are retained on disk. The separate legacy `--classic` capture interface and Node.js prototype remain development tools.

The new plugin is an OpenAI API integration inside Observe. It has its own local history, and does not connect to or synchronize with chatgpt.com. The retired ChatGPT Desktop/MCP bridge remains disabled.

## Attribution fixes in 0.9.0

Delayed Windows process-start notifications no longer discard an existing tracked root. New trace records include the actual creation time. PID reuse is bounded by process identity and lifetime; ETW identities are captured before aggregation, and closed TCP rows keep their original owner. Recorded-launch chats refresh from that same recording. Network evidence is interleaved with other categories when preparing small-model requests, so a file-event flood cannot remove all network rows. Reading a ps1 with Get-Content is no longer treated as proof it was executed.

The supplied Cities2 recording was replayed read-only with the corrected correlator: 4 linked processes and 30 linked records, including 16 DNS events. The later Network screenshot used a different PID and must be tracked as a separate instance. Events already discarded by older versions cannot be recreated unless retained elsewhere. These changes improve evidence attribution; model prose is still not a guaranteed verdict.

## Evidence and its limits

Executable questions match recorded image paths and select the latest matching process lifetime. Retained local process/network identity can support attribution when a Sysmon launch is unavailable. Full paths support spaces. Process GUIDs connect the launch to its descendants; recorded exits and PID reuse bound attribution. Descendants can outlive their parent. A filename matching multiple paths requires a full path. If the launch record is missing, matching retained image/GUID events are identified as partial evidence. Live network and PowerShell PID records are attached only when a corresponding process lifetime is established. Machine DNS cache entries are not attributed to a program.

PowerShell `.ps1` questions reuse logged script-block paths, ISE invocation records, command lines and related host/descendant evidence. A shared PowerShell host can execute unrelated scripts. Script text is evidence of intent, not proof that each command completed. ISE event 24577 records that a script was started; it contains neither its code nor proof of completion.

Module records can be emitted after their commands execute. Correlation uses host/runspace/pipeline identifiers to group those records and retains the corresponding earlier script text or ISE start marker. A final module record does not replace the run's starting boundary. For a module-only match, the first available record is a partial boundary; earlier actions may be absent.

Chat questions do not open or execute the named program or script. Only the explicit Tracked apps launch action executes the selected executable. Observe reads retained Windows event logs and its persistent local evidence journal. Logging must already have captured an action to report it. Missing records do not prove that no action occurred.

| Evidence | Meaning |
|---|---|
| Sysmon 1 / 5 | Process start / exit |
| Sysmon 3 / 22 | Network connection / DNS query |
| Sysmon 11 | File created or overwritten; does not distinguish the two or cover every edit |
| Sysmon 2 | File creation timestamp changed; not proof of content modification |
| Sysmon 23 / 26 | File deletion; 26 records metadata without archiving the file |
| Sysmon 12 / 13 / 14 | Registry object creation/deletion, value set, or rename |
| PowerShell 4103 / 4104 | Recorded module/script text |
| PowerShell 24577 | ISE started the named script; invocation evidence only |
| Observe process samples | Already running, appeared, or disappeared between samples; not an exact process start/exit record |

Directory paths derived from files do not establish directory creation/deletion. Connections do not prove a human website visit. Browser history, HTTPS contents and full URLs are not captured. Work delegated to unrelated services may be absent. Model answers can be wrong; inspect their evidence. Citation IDs are checked against the exact snapshot for that answer. Stable short citationId values are sent alongside original event IDs. Unmatched references are marked unverified and cannot open an unrelated event. Citation warnings preserve the generated answer and explain that Observe could not verify it. Partial or unverified answers are not included as assistant context in later API requests. Free-text claims are not mechanically proven.

Each evidence search is bounded by 25,000 events per channel, 48 MB of XML and 45 seconds, newest first. Program searches prioritize Sysmon; script searches prioritize PowerShell. Up to 5,000 related events / 16 MB are retained before API minimization. Limits, unreadable channels and gaps are disclosed. All retained logs remains subject to these bounds and log rotation.

## API key, requests and history

Windows DPAPI encrypts the saved key for the current Windows user. It is never returned in the WebView state or included in the evidence payload. Removing the plugin or uninstalling Observe clears its key. Conversations remain until individually deleted.

Clicking Send shares the question, recent chat context and the current relevant evidence snapshot with OpenAI. There are no automatic API calls. The composer and plugin setup disclose this. Requests use the fixed HTTPS Responses API endpoint, streaming, `store:false`, no model tools and a 120-second provider timeout. API access and billing are separate from ChatGPT subscriptions. `store:false` does not mean zero provider retention. Tests make no real paid API requests.

Evidence is minimized again for each selected model, with recent conversation context, the current question, instructions and output room included in the budget. UTF-8 byte counts provide conservative token upper bounds, not exact usage estimates. Older messages and repetitive events are omitted first; large fields are shortened, with coverage warnings. The current question is never silently truncated. Initial evidence minimization also caps the source snapshot at 350 events / approximately 150 KB. Best-effort redaction replaces user directory names and common secret patterns; event text, IPs and domains may still be sensitive.

| Model | App input cap (conservative token bound) | Output budget (includes reasoning) | Maximum evidence events |
|---|---:|---:|---:|
| GPT-5 nano | 24,000 | 8,000 | 80 |
| GPT-5.6 Luna | 40,000 | 8,000 | 150 |
| GPT-5.6 Terra | 64,000 | 12,000 | 250 |
| GPT-5.6 Sol | 80,000 | 12,000 | 350 |
| GPT-6 Astra | 96,000 | 16,000 | 350 |

These app budgets stay below published context/output limits and bound request cost. If reasoning consumes the output budget before an answer finishes, the error explains that limit. API limits, account quota and model access can still reject requests. Model specifications and standard price hints were checked on 2026-09-17 against the official [model comparison](https://developers.openai.com/api/docs/models/compare), [GPT-5 nano](https://developers.openai.com/api/docs/models/gpt-5-nano) and [Luna](https://developers.openai.com/api/docs/models/gpt-5.6-luna) documentation.

Up to 19 prior complete messages fit within a quarter of the input budget. Follow-ups reuse the latest minimized snapshot; use **Refresh evidence** to gather more after switching to a larger model. Chats have an 80-message limit; start a new conversation when reached. The sidebar lists the latest 200 conversations; older files remain on disk.

Chats and their redacted evidence snapshots are saved as JSON in `%LOCALAPPDATA%\ObserveDesktop\observer-chats`. Chat text is not encrypted. Files rely on Windows user-directory permissions. Key storage is separate in `plugins.json`. No browser storage contains the key.

API references: [Responses API](https://developers.openai.com/api/reference/cli/resources/responses/methods/create), [streaming responses](https://developers.openai.com/api/docs/guides/streaming-responses).

## Local sensors and plugins

Activity, Network and PowerShell scripts remain usable without an API key. TCP tables are sampled every second and DNS cache every three seconds. Administrator-only ETW adds DNS and aggregated TCP/UDP transfer evidence. Short connections can be missed.

Activity retains up to 2,000 records with separate allowances: 1,200 network, 350 process, 200 script text/ISE invocations, 150 module records and 100 other events. The selected filter is applied before taking 250 rows. Startup reads recent process and PowerShell events. Running processes are sampled every three seconds while monitoring is enabled, providing visibility without Sysmon permissions. Very short-lived processes can be missed, and samples alone establish no file or registry changes.

**PowerShell scripts** reads PowerShell channels independently of network/Sysmon traffic, prioritizes script text and invocations, and refreshes every five seconds while visible and idle. The default period is one hour, with options up to seven days. Reads are bounded to 20 seconds and 5,000 retained records; the page displays gaps and missing channel/access details. A policy-enabled badge does not mean every earlier PowerShell session produced script text.

Version 0.7.1 also fixes timestamp formatting in every Windows event-log query: invariant UTC dates replace regional formatting that could silently return no matches on systems using dots between hours, minutes and seconds.

If Sysmon reports access denied, use **Settings → Restart as administrator**. Running the Sysmon service and having permission to read its logs are separate conditions. Sensor setup and PowerShell logging enablement remain explicit user actions with Windows elevation as needed. Observe does not enable logging merely by opening the app or enabling the observer plugin.

**Enable PowerShell logging** enables Script Block Logging and Module Logging for Windows PowerShell and PowerShell Core, plus available operational channels. Backups live under `%ProgramData%\ObserveDesktop`. Open a new PowerShell session after enabling it. Missing PowerShell Core providers are reported rather than installed. Settings → Restore previous settings restores the saved sensor/policy configuration as administrator. Backups are retained after partial failures.

### A script ran, but its Observer snapshot is empty

An existing PowerShell or ISE process may still use the policy it loaded before logging was enabled. Version 0.7.1 compares running host start times with Observe's saved logging-setup time and displays a warning in Settings, PowerShell scripts, and empty Observer snapshots. Save work, close that PowerShell/ISE window, and open a fresh session before another run. Observe never closes the host or reruns the user's script automatically. The missing optional PowerShell 7 provider is separate from Windows PowerShell/ISE logging.

The new empty-snapshot notice says that recorded activity could not be linked to the run; it does not deny the user's reported execution. Model instructions explain this distinction and treat pasted console output as user-provided evidence. Retrying an empty snapshot automatically gathers current evidence, including in saved chats. The application cannot reconstruct unlogged historical commands, and current script contents alone do not prove earlier execution or completion.

The default dashboard now uses the full-stop Game performance workflow described above. The legacy classic capture interface retains its older reduced Gaming profile for development; it is not the new dashboard pause workflow.

UniFi remains an optional read-only Network Integration API plugin. Its encrypted credentials are separate. It provides current sites, clients and devices, not historical flows or historical IP ownership.

## Install and build

Extract `dist\Observe-Windows-0.8.0.zip` and run **Observe-Setup.exe**, or run **Observe.exe** portably. Installation uses `%LOCALAPPDATA%\Programs\Observe`, a Start menu shortcut and an Installed apps entry. Close older instances before updating. The binary is unsigned, Windows x64 only, with .NET bundled. Microsoft Edge WebView2 Evergreen Runtime is required separately. Keep the dependency licenses with the app.

Uninstall keeps Sysmon running by default. Removing Sysmon is an explicit separate option requiring administrator access; other tools using it lose those events. PowerShell policies, saved chats/evidence and sensor backups are retained. Only receipt-listed app files and owned installation entries are removed. Saved plugin keys are cleared.

Build with the .NET 10 SDK:

    .\windows\Build.ps1 -LiveTests
    .\windows\Package-Source.ps1

Outputs are `dist\Observe-Windows-0.8.0`, its ZIP, and `dist\Observe-Source.zip`. Build gates cover self-tests, existing correlation tests, observer correlation/API/storage tests, tracked launch/ThreatFox/network/game-plan tests, native UI construction and optional real WebView/live sensor tests. UI tests use an isolated profile and a fake API provider for chat requests. They do not modify machine logging, remove Sysmon or spend API credits. The release includes JSON test results and SHA-256 hashes.
