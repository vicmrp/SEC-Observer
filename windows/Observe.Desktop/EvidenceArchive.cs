using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace Observe;

// Append-only daily journals. UI limits never remove the underlying evidence.
public sealed class EvidenceArchive
{
    readonly object gate=new();
    readonly string root;
    readonly string writer=Guid.NewGuid().ToString("N");
    readonly HashSet<string> recentIds=[];
    readonly Queue<string> idOrder=[];
    static readonly JsonSerializerOptions Compact=new(Evidence.Json){WriteIndented=false};
    public EvidenceArchive(string root){this.root=root;Directory.CreateDirectory(root);}
    public void Append(IEnumerable<EvidenceEvent> events)
    {
        lock(gate)foreach(var day in events.Where(e=>!recentIds.Contains(e.Id)).DistinctBy(e=>e.Id).GroupBy(e=>e.Timestamp.UtcDateTime.ToString("yyyyMMdd")))
        {
            using var stream=new FileStream(Path.Combine(root,day.Key+"-"+writer+".ndjson"),FileMode.Append,FileAccess.Write,FileShare.Read);
            using var output=new StreamWriter(stream,new UTF8Encoding(false),65536,leaveOpen:true);
            foreach(var e in day){output.WriteLine(JsonSerializer.Serialize(e,Compact));recentIds.Add(e.Id);idOrder.Enqueue(e.Id);}
            output.Flush();stream.Flush(true);
            while(idOrder.Count>100000)recentIds.Remove(idOrder.Dequeue());
        }
    }
    public EvidenceEvent[] Read(DateTimeOffset start,DateTimeOffset end)
    {
        lock(gate)
        {
            var result=new Dictionary<string,EvidenceEvent>();
            var from=start.UtcDateTime.ToString("yyyyMMdd");var to=end.UtcDateTime.ToString("yyyyMMdd");
            foreach(var path in Directory.EnumerateFiles(root,"*.ndjson").Order())
            {
                var day=Path.GetFileName(path)[..8];if(string.CompareOrdinal(day,from)<0||string.CompareOrdinal(day,to)>0)continue;
                using var input=new StreamReader(new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite));
                while(input.ReadLine() is {} line)
                {
                    // An interrupted final write cannot invalidate earlier complete records.
                    try{var e=JsonSerializer.Deserialize<EvidenceEvent>(line,Compact);if(e is not null&&e.Timestamp>=start&&e.Timestamp<=end)result.TryAdd(e.Id,e);}
                    catch(JsonException){}
                }
            }
            var ordered=result.Values.OrderBy(e=>e.Timestamp).ToArray();
            foreach(var e in ordered.TakeLast(100000))if(recentIds.Add(e.Id))idOrder.Enqueue(e.Id);
            while(idOrder.Count>100000)recentIds.Remove(idOrder.Dequeue());
            return ordered;
        }
    }
    public void Clear(){lock(gate){foreach(var file in Directory.GetFiles(root,"*.ndjson"))File.Delete(file);recentIds.Clear();idOrder.Clear();}}
    public void ImportLegacy(string dataRoot)
    {
        var marker=Path.Combine(root,"legacy-imported");if(File.Exists(marker))return;
        foreach(var folder in new[]{"tracked-launches","sessions"})
        {
            var directory=Path.Combine(dataRoot,folder);if(!Directory.Exists(directory))continue;
            foreach(var path in Directory.EnumerateFiles(directory,"*.json"))
                try{using var doc=JsonDocument.Parse(File.ReadAllText(path));if(doc.RootElement.TryGetProperty("events",out var events))Append(events.Deserialize<EvidenceEvent[]>(Evidence.Json)??[]);}catch(JsonException){}
        }
        File.WriteAllText(marker,DateTimeOffset.UtcNow.ToString("O"));
    }
}

public sealed record StorageCategory(string Name,long Bytes,int Files);
public static class LocalLogStorage
{
    static readonly string[] Folders=["evidence","tracked-launches","sessions","observer-chats","mod-canary"];
    static IEnumerable<string> Files(string root)=>Folders.SelectMany(name=>Directory.Exists(Path.Combine(root,name))?Directory.EnumerateFiles(Path.Combine(root,name),"*",SearchOption.TopDirectoryOnly):[])
        .Where(f=>Path.GetExtension(f) is ".json" or ".ndjson").Concat(new[]{"process-snapshot.json","known-apps.json"}.Select(f=>Path.Combine(root,f)).Where(File.Exists));
    public static object Usage(string root)=>new{at=DateTimeOffset.UtcNow,path=root,bytes=Files(root).Sum(f=>new FileInfo(f).Length),categories=Folders.Select(name=>{var files=Files(root).Where(f=>Path.GetFileName(Path.GetDirectoryName(f))==name).ToArray();return new StorageCategory(name,files.Sum(f=>new FileInfo(f).Length),files.Length);}).Append(new("App & process history",Files(root).Where(f=>Path.GetDirectoryName(f)==root).Sum(f=>new FileInfo(f).Length),Files(root).Count(f=>Path.GetDirectoryName(f)==root))).ToArray(),scope="Observe's saved evidence, recordings, chats and app history. Windows event logs, WebView cache, API keys and sensor restoration backups are separate."};
    public static void Export(string root,string destination)
    {
        // A fixed allowlist ensures credentials and sensor backups never enter a log export.
        using var zip=ZipFile.Open(destination,ZipArchiveMode.Create);
        foreach(var file in Files(root)){var entry=zip.CreateEntry(Path.GetRelativePath(root,file),CompressionLevel.Fastest);using var input=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite);using var output=entry.Open();input.CopyTo(output);}
        using var readme=new StreamWriter(zip.CreateEntry("README.txt").Open());readme.Write("Observe local evidence export. Raw commands, script text, paths and destinations can contain private data. API keys, browser cache and sensor backups are excluded. Windows event logs are not part of this export.");
    }
    public static void Clear(string root){foreach(var file in Files(root))File.Delete(file);}
}
