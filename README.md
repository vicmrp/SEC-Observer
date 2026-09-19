# Observe

**v0.12.1-beta-vibe-coded** · MIT · Windows x64

[Download the installer](https://github.com/vicmrp/SEC-Observer/releases/tag/v0.12.1-beta-vibe-coded) · [UVM and setup guide](https://vezit.net#observer)

**0.12.1 connection fix:** Observe can now connect to UVM when Observe runs as administrator and Cities II runs normally under the same Windows account. The bridge checks the actual user SID and prevents server impersonation. Local and subscribed UVM builds use the same connection; UVM 0.5 or later does not need replacement for this fix.

The installer starts with no optional plugins selected. Choose Cities II mod observer for a local UVM connection; add Windows forensic logging if you want Sysmon and PowerShell evidence. Sysmon is downloaded from Microsoft and signature-checked. Existing Sysmon rules are reused, never silently replaced. AI, ThreatFox and UniFi require your own credentials after installation. A separate unchecked option starts Observe at sign-in. Updates retain existing plugin configuration.

UVM 0.5 and Observe reconnect automatically while both are running. Code-only and loaded-only filters synchronize in both directions and persist across restarts. A green check indicates a recent successful exchange. Offline data is explicitly marked as a previous snapshot. No Windows evidence or mod binaries are automatically sent to UVM or OpenAI.

**Requirements:** Windows 10/11 x64 and Microsoft Edge WebView2 Runtime. The .NET runtime is included. The installer and binaries are currently unsigned. The harmless Cities II test mod is built from source and is only installed when explicitly requested in the test UI.

## Build

Install .NET SDK 10 and the Cities: Skylines II modding references, then run `windows/Build.ps1`. Set `GameManagedPath` in your local MSBuild configuration for a nonstandard game installation. Builds go to `dist/`, which is excluded from source control. Automated checks use isolated fixtures; do not run live sensor tests on a machine you cannot reconfigure.

## Privacy

The source and release package exclude local settings, API credentials, observations, test output, browser profiles and build debug files. API keys entered by a user are stored locally using Windows DPAPI. The earlier Node prototype is retained as source, not part of the Windows installer.

## Earlier changes

**Windows 0.8.0** adds tracked app launches, a restart-based game performance mode, an optional ThreatFox plugin and frozen Network Flows / Activity views. Recent activity and Network pulse have been removed from Overview.

Launch apps in **Workspace → Tracked apps**, then inspect their process tree, destinations, recorded changes and review signals. **Game performance** saves recordings, reverses Observe-owned sensor changes, and restarts without collectors; **Restore monitoring** restores the saved configuration. ThreatFox is disabled until configured and only queries indicators when you click Check. Network tables update on demand and use local executable icons; country flags require an optional local CIDR-country map.

Observation is not isolation or a malware verdict. An in-process mod shares the game process, so it cannot be distinguished reliably from other game code. No rule matches or ThreatFox results do not establish safety.

The observer chat includes **Workspace → chatGPT observer** with a five-model dropdown, model-specific request budgets, and expandable, copyable provider error logs. Luna is the default for new setups; existing model choices are preserved.

Version 0.7.2 preserves generated answers when streaming fails, Stop is pressed, or a citation cannot be verified. Errors appear beneath the text with a copyable diagnostic log. Stable short citation IDs reduce copying mistakes; unknown references remain visibly unverified. Text is checkpointed during streaming and retained in saved chat history.

The 0.7.1 patch identifies PowerShell/ISE sessions that predate Observe's logging setup, displays an explicit notice when no activity could be linked to a run, and refreshes empty snapshots automatically on the next message. Existing PowerShell sessions may need to be closed and reopened after logging is enabled; restarting Observe alone does not restart those hosts. Missing telemetry is never evidence that a user-reported execution did not happen.

Script correlation also preserves script text and earlier changes when module records arrive at the end of execution. Host, runspace and pipeline IDs separate repeated module invocations. The live UI gate verifies that a harmless fresh script's recorded text reaches the Observer request using the production evidence reader and a simulated API provider.

PowerShell scripts now refresh automatically, show retained ISE invocation records alongside script text, and search the last hour by default. Windows log queries use invariant UTC timestamps, fixing empty results on regional settings with dot-separated times. Activity filters select their event type before limiting rows. Separate buffer allowances prevent network traffic from hiding process and script records, and sampled running processes appear even without access to Sysmon.

The optional plugin requires your OpenAI API key. Configure it in **Plugins** or from the observer workspace. Your key is encrypted by Windows; chats stay on this PC. Sending shares relevant Windows evidence and chat context with OpenAI. Local Activity, Network and PowerShell views still work without credentials.

Example: `I just opened "C:\Games\Example\Game.exe". Please tell me what this program did to my computer.`

The old past-activity investigation interface and its dashboard commands have been removed. Executable matching now follows recorded process GUIDs and descendants, and script questions reuse the existing PowerShell correlation engine. Answers are limited to recorded evidence; missing historical logs cannot be reconstructed.

Run **dist/Observe-Windows-0.12.1-beta-vibe-coded/Observe-Setup.exe** to install, or **Observe.exe** for portable use. Source and future builds live in your repository checkout.

See [Windows instructions, privacy, limits and build steps](windows/README.md). Build with **windows/Build.ps1 -LiveTests**, then **windows/Package-Source.ps1**. The .NET runtime is bundled; WebView2 Runtime is required separately.

The earlier Node.js prototype and native `--classic` capture UI remain development tools. The retired Desktop/MCP bridge remains disabled. The observer plugin uses the OpenAI API and its own local history; it does not synchronize with chatgpt.com.
