using System;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using UnityEngine;
using Colossal.Logging;
using Game;
using Game.Modding;
using Game.SceneFlow;

namespace ObserveCanaryMod
{
    // Deliberately harmless: no arbitrary target paths, networking, child processes,
    // registry changes or game/save changes. A new arm ID permits one synthetic read.
    public sealed class Mod : IMod
    {
        static readonly ILog Log = LogManager.GetLogger("ObserveCanaryMod.Mod").SetShowsErrorsInUI(false);
        GameObject runnerObject;
        string modPath = "";
        string attempted = "";
        string lastStatus = "";
        bool disposed;
        public void OnLoad(UpdateSystem updateSystem)
        {
            Log.Info("Loaded harmless Observe canary test. Idle until Observe arms a test. No user documents will be read.");
            if (GameManager.instance.modManager.TryGetExecutableAsset(this, out var asset)) modPath = asset.path;
            runnerObject = new GameObject("Observe harmless canary test");
            UnityEngine.Object.DontDestroyOnLoad(runnerObject);
            runnerObject.AddComponent<CanaryRunner>().Tick = Poll;
            Poll();
        }
        public void OnDispose() { disposed = true; if (runnerObject != null) UnityEngine.Object.Destroy(runnerObject); Log.Info("Canary test mod disposed."); }
        void Note(string text) { if (text != lastStatus) { lastStatus = text; Log.Info(text); } }
        void Poll()
        {
            if (disposed) return;
            try
            {
                var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Observe Canary Lab", ".control").Replace('\\', '/');
                var arm = Path.Combine(root, "armed.txt").Replace('\\', '/');
                NoLinks(arm);
                string[] lines;
                try { if (new FileInfo(arm).Length > 256) return; lines = File.ReadAllLines(arm); }
                catch (FileNotFoundException e) { Note("Idle: no armed test at " + arm + ". " + e.Message); return; }
                catch (DirectoryNotFoundException e) { Note("Idle: control directory is unavailable at " + root + ". " + e.Message); return; }
                if (lines.Length != 3 || lines[0] != "OBSERVE-CANARY-1" || !Guid.TryParseExact(lines[1], "D", out var id) || !DateTimeOffset.TryParse(lines[2], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var until)) { Note("Idle: invalid canary arm record."); return; }
                if (until <= DateTimeOffset.UtcNow || until > DateTimeOffset.UtcNow.AddMinutes(21)) { Note("Idle: canary test is expired or has an invalid expiry."); return; }
                if (attempted == id.ToString()) return;
                var run = Path.Combine(root, id + ".ready");
                if (!File.Exists(run) || File.Exists(Path.Combine(root, id + ".stop"))) { Note("Idle: Windows sensor is not ready for test " + id); return; }
                NoLinks(run);
                attempted = id.ToString();
                var target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Observe Canary Lab", id.ToString(), "canary.txt").Replace('\\', '/');
                NoLinks(target);
                if (!File.Exists(target) || new FileInfo(target).Length > 1024) throw new IOException("Synthetic canary missing or too large; test skipped.");
                var before = DateTimeOffset.UtcNow;
                int bytes;
                // The mock suspicious action: read a synthetic document outside the game.
                using (var input = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                { var buffer = new byte[1024]; bytes = input.Read(buffer, 0, buffer.Length); Array.Clear(buffer, 0, buffer.Length); }
                var after = DateTimeOffset.UtcNow;
                using (var process = Process.GetCurrentProcess())
                {
                    var receipt = new Receipt { SessionId = id.ToString(), Pid = process.Id, ProcessStartUtc = process.StartTime.ToUniversalTime().ToString("O"), StartedUtc = before.ToString("O"), CompletedUtc = after.ToString("O"), Bytes = bytes, Mod = "Observe.CanaryMod", ModPath = modPath };
                    using (var sha = SHA256.Create()) using (var dll = File.OpenRead(receipt.ModPath)) receipt.ModSha256 = BitConverter.ToString(sha.ComputeHash(dll)).Replace("-", "").ToLowerInvariant();
                    var receiptPath = Path.Combine(root, id + ".receipt.json"); NoLinks(receiptPath);
                    using (var output = new FileStream(receiptPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) new DataContractJsonSerializer(typeof(Receipt)).WriteObject(output, receipt);
                }
                Log.Info("Harmless test read completed. Session=" + id + "; synthetic path=" + target + "; bytes=" + bytes + ". Windows sensor evidence must confirm the process read separately.");
            }
            catch (Exception e) { Note("Canary test skipped/failed: " + e.GetType().Name + ": " + e.Message); }
        }
        static void NoLinks(string path)
        {
            for (var current = Path.GetFullPath(path); !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
                if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException("Links are not allowed in the canary test path.");
        }
    }
    // Unity and Colossal logging APIs must stay on the game's main thread.
    public sealed class CanaryRunner : MonoBehaviour
    {
        public Action Tick;
        float next;
        void Update() { if (Time.unscaledTime < next) return; next = Time.unscaledTime + 3; Tick?.Invoke(); }
    }
    [DataContract] public sealed class Receipt
    {
        [DataMember] public string SessionId;
        [DataMember] public int Pid;
        [DataMember] public string ProcessStartUtc;
        [DataMember] public string StartedUtc;
        [DataMember] public string CompletedUtc;
        [DataMember] public int Bytes;
        [DataMember] public string Mod;
        [DataMember] public string ModPath;
        [DataMember] public string ModSha256;
    }
}
