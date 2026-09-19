using System.Text.Json;

namespace Observe;

public sealed class SessionStore
{
    public string DirectoryPath { get; }
    readonly SemaphoreSlim gate=new(1,1);
    public SessionStore(string? directory=null) { DirectoryPath=directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ObserveDesktop","sessions"); Directory.CreateDirectory(DirectoryPath); }
    string FilePath(string id) => Path.Combine(DirectoryPath,Guid.Parse(id)+".json");
    public async Task Save(Observation observation)
    {
        var text=JsonSerializer.Serialize(observation,Evidence.Json);
        await gate.WaitAsync();
        try { var path=FilePath(observation.Id); await File.WriteAllTextAsync(path+".tmp",text); File.Move(path+".tmp",path,true); }
        finally { gate.Release(); }
    }
    public List<Observation> Load()
    {
        var result=new List<Observation>();
        foreach(var path in Directory.EnumerateFiles(DirectoryPath,"*.json").OrderByDescending(File.GetLastWriteTimeUtc).Take(30))
        {
            if(new FileInfo(path).Length>30_000_000) continue;
            try
            {
                var s=JsonSerializer.Deserialize<Observation>(File.ReadAllText(path),Evidence.Json); if(s is null) continue;
                if(s.Status is "observing" or "loading") { s.Status="interrupted"; s.End=s.Events.Count>0 ? s.Events.Max(e=>e.Timestamp) : s.Start; s.Warnings.Add("Observe closed before capture finished. Evidence is incomplete."); }
                result.Add(s);
            }
            catch(JsonException) { }
        }
        return result;
    }
}
