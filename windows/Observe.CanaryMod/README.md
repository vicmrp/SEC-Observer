# Harmless Cities II canary exercise

This mod is a deliberate, opt-in test of Observe's file-read alert pipeline. It is not malware, an antivirus, or a sandbox.

## Run it

1. Open Observe 0.9.1 → **Plugins** → **Cities II mod observer** → **Enable plugin**. The plugin is disabled by default. Close Cities II and click **Install test mod** in its workspace.
2. Click **Arm test**. Approve Windows' administrator prompt for the temporary ETW file-read sensor.
3. Start Cities II normally through Steam/its launcher. Ensure the local `Observe.CanaryMod` is enabled. If it was already loaded, it notices a newly armed test within three seconds.
4. Observe raises a canary alert with the process, path, timestamp and Windows completion status when recorded. Windows notification settings or fullscreen gaming can suppress the balloon; the persistent in-app alert and saved evidence remain.
5. Click **Ask chatGPT observer** to prepare a conversation about this test. Sending uses your optional OpenAI API key and shares only the displayed evidence context. No API request is made by installation, arming or detection.
6. Stop the test when finished. Close Cities II before **Remove test mod & synthetic files**. Disable the Observe integration from Plugins. Disabling disarms the test, pauses its evidence polling and hides its workspace; an installed game mod remains idle until explicitly armed again. Saved evidence is retained.

## Exactly what it does

- While loaded, the mod checks a small Observe control file every three seconds on the Unity main thread.
- It stays inactive without a current arm ID and ready sensor marker.
- Once per arm ID it reads at most 1,024 bytes from `Documents\Observe Canary Lab\<test GUID>\canary.txt`. Observe creates that new, uniquely named file with fake text. It contains no personal information.
- The test refuses symbolic links/junctions in its canary/control paths, expired IDs and oversized targets. No arbitrary target path is accepted from the control file.
- It discards the read contents. Its receipt includes process lifetime, time, read byte count and its own DLL identity/hash. It also logs a message in `Cities Skylines II\Logs\ObserveCanaryMod.Mod.log`.
- It has no networking, child-process launch, credential collection, persistence registration, registry writes, game-state changes or save modification.

## Independent evidence and its limits

The short-lived elevated Observe helper creates a uniquely named Windows ETW session. It records only reads of this exact synthetic file and related completion records. Other file contents/paths are not saved by this sensor. It does not change Sysmon, Windows audit policy or install a driver. It stops after 20 minutes, on Stop, on performance-mode activation, or on normal Observe shutdown.

A Windows FileIO/Read record proves a **process requested a read**. A matching operation-end record with NTSTATUS `0x00000000` provides successful completion evidence. A request without that completion is labelled as such. Requested byte count is not claimed as a completed transfer count. ETW loss is displayed; missed events never establish safety.

The mod's receipt is **cooperative self-report**. Matching the process creation time, PID and action interval connects it to the Windows records for this controlled exercise. It does not independently identify a managed caller in an arbitrary mod, and another mod could forge a receipt. Receipt-only tests do not produce an independent Windows finding. The alert is a local deterministic rule; it does not depend on an AI verdict.

This feature covers the synthetic canary. It does not monitor every personal file or establish that an arbitrary mod stays within the game. Broader protection needs selected file/registry/network tracing and an expected-behavior policy; reliable per-mod attribution additionally needs runtime/call-stack instrumentation. Legitimate saves, configuration and game logs often live outside the installation directory.

## Saved data and building

Saved status, receipts and events are stored in `%LOCALAPPDATA%\ObserveDesktop\mod-canary`. A small activation/ready/receipt handoff uses `Documents\Observe Canary Lab\.control` so both the game and Observe can see it, including when Observe is started by a packaged app that redirects local app data. The validated receipt is copied into the saved evidence folder. Read records also enter Observe's persistent evidence journal and matching tracked process recordings. Overview's log export includes the canary JSON/NDJSON evidence. Synthetic documents and game handoff files are separately removed by the cleanup button.

Build `Observe.CanaryMod.csproj` with .NET SDK and the installed Cities II managed assemblies (or `-p:GameManagedPath=...`). No proprietary game DLLs are redistributed. `windows\Build.ps1` builds and embeds the resulting mod in Observe. Source is included so its exact actions can be reviewed.
