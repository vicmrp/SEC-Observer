# Observe integration (UVM 0.5.0 / Observe 0.11.0-beta-vibe-coded)

In the game, open **Options → Unified Verified Mods → Scan**. The connection is enabled by default and reconnects automatically. An explicit opt-out remains respected. In Observe, enable **Cities II mod observer** under **Plugins**, then open **Cities II mods**. The green connection check means a recent local exchange succeeded; it expires after 12 seconds without another exchange.

The Scan tab uses C# widgets rendered by the game's existing Modding status-row component. Mod thumbnails come from downloaded metadata, with a blank icon for packages without a thumbnail. Expand a row to inspect build results. The existing Report tab and background scan remain available. Build checks are labelled **last scan**: rescan after changing files or updating mods. A matching build is not a safety audit.

Observe's searchable table separates loaded code mods reported by the game's ModManager from downloaded or local packages whose load has not been observed. Cached packages can be disabled, assets-only or older revisions. Click a mod for its description, assemblies, last signed build result, compiled API references, cooperative receipts, and shared game process activity.

**Filters:** the game has a **Filters** tab with **Code mods only** enabled by default and an optional **Loaded mods only** checkbox. Choices persist between launches and synchronize in both directions with Observe. The latest edit wins after reconnect, with a persisted revision and deterministic tie-breaker preventing stale replay. Observe's table initially shows code mods. Classification looks for executable files and scripts in package subfolders, independently of build verification or compiled API references. Packages with incomplete classification remain visible; content-only packages are hidden. The Report tab retains the complete scan.

## Evidence boundaries

* **Inventory:** cooperative data from UVM inside the game. It is not tamper-resistant against other code running in the same process.
* **Build result:** the last UVM package scan. Existing signature/hash checks are unchanged. The new local development build of UVM is not automatically verified by the published package's attestation.
* **Compiled references:** direct calls to selected file, network and process APIs found by reading DLL metadata/IL. These indicate possible capabilities, not proof that calls ran. Reflection, native code, indirect calls and uninspected assemblies can be missed. Native DLLs may report inspection unavailable.
* **Windows activity:** Observe's retained process/network/file events for the game's PID and creation time and recorded descendants. They are shared game evidence. They do not identify which mod made a call. The game itself legitimately uses the network and files outside its installation folder, including saves and logs. Sysmon/file coverage depends on existing sensors and permissions; the bridge does not enable or reconfigure sensors.
* **Cooperative receipts:** optional mod reports, clearly labelled self-reported. Absence of receipts is not evidence of inactivity. Other in-process code can forge them.

The canary exercise remains separate. A SearchProtocolHost.exe read of the synthetic document is not attributed to Cities II or a mod.

AI comparison of a mod's description, source and behavior is not implemented in this version. The integration performs no automatic AI upload or safety classification.

## Local protocol and limits

The transport is a Windows named pipe named `UVM.Observe.v2.<Windows user SID>`, with an ACL restricted to the current user and an explicit denial for network logons. There is no TCP listener. The endpoint exchanges diagnostic snapshots and two list-filter preferences; it accepts no path, executable or remote-control commands.

Messages are length-prefixed little-endian 32-bit UTF-8, bounded to 8 MiB. Observe sends schema 2 JSON containing a random 32-hex nonce and its bounded filter revision. UVM merges the filter revision and returns schema 2 JSON containing the merged filters, that nonce, a game-session ID, process PID/start time, inventory generation time, scan time, mods and at most 200 receipts. Observe checks the kernel-reported pipe server PID, Cities2.exe process identity, process creation time, nonce, schema, limits and freshness, then returns `ACK <nonce>`. UVM checks the kernel-reported client process is Observe.exe. This is a local interoperability check, not a code-signing identity guarantee.

Observe polls every five seconds while its optional plugin is enabled, including when Windows collectors are paused. UVM snapshots game APIs on Unity's main thread every five seconds. Disk inventory refreshes every 30 seconds; icons and compiled inspection are cached by file modification time. Reads are bounded (256 package folders per root, 32 root DLLs per package, 32 MiB per inspected DLL, one million IL instructions, 60 distinct API references per DLL). The native Options list displays up to 512 inventory rows. No DLLs or local activity are uploaded through this bridge.

Turn off either connection to disconnect. Closing Observe stops its polling; unloading UVM closes the pipe and releases the worker. Existing registry requests still occur only through the normal user-initiated UVM scan.

## Optional mod API

Mods that already reference UVM can call:

```csharp
Uvm.ObserveActivity.Record("file", "Saved settings", settingsPath);
Uvm.ObserveActivity.Record("network", "Requested update metadata", "https://example.com");
```

Categories are `file`, `network`, `process`, and `lifecycle`. UVM derives the calling assembly; the API does nothing when sharing is disabled and never throws into the mod. Keep operation/target strings free of secrets or file contents. Network targets are reduced to an origin; query strings, paths, credentials and bodies are omitted. The ring buffer retains 200 receipts in memory and clears when UVM sharing is disabled or UVM unloads. These reports remain cooperative claims, even when the calling assembly is identified.

For assemblies Unity loads from bytes, the file location is empty. Receipts also carry the assembly's full name and module ID (MVID), so Observe can associate them with the corresponding game-reported module without guessing from its name alone.

The protocol source is `Shared/ObserveProtocol.cs` in UVM and `windows/Observe.Desktop/ObserveProtocol.cs` in Observe. Keep these identical when changing the protocol. Increment its schema and pipe name for incompatible changes.
