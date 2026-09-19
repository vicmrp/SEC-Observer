using System;
using System.Globalization;
using System.IO;

namespace Uvm.Bridge
{
    // Replicated preferences only. A persisted logical clock makes reconnects idempotent;
    // simultaneous edits converge by revision and unique edit ID, without echo loops.
    public sealed class BridgeFilters
    {
        readonly object gate=new object();
        readonly string path;
        long revision;
        string edit="00000000000000000000000000000000";
        bool code=true,loaded;
        public BridgeFilters(string path,bool initialCode=true,bool initialLoaded=false)
        {
            this.path=path;
            try{if(File.Exists(path)){Merge(File.ReadAllText(path));return;}}catch(IOException){}catch(UnauthorizedAccessException){}catch(InvalidDataException){}
            Set(initialCode,initialLoaded);
        }
        public bool CodeOnly {get{lock(gate)return code;}}
        public bool LoadedOnly {get{lock(gate)return loaded;}}
        public string Wire {get{lock(gate)return revision.ToString(CultureInfo.InvariantCulture)+"|"+edit+"|"+(code?"1":"0")+"|"+(loaded?"1":"0");}}
        public void Set(bool codeOnly,bool loadedOnly)
        {
            lock(gate){if(code==codeOnly&&loaded==loadedOnly)return;revision=Math.Max(DateTime.UtcNow.Ticks,revision+1);edit=Guid.NewGuid().ToString("N");code=codeOnly;loaded=loadedOnly;Save();}
        }
        public bool Merge(string wire)
        {
            if(wire==null||wire.Length>100)throw new InvalidDataException("Invalid filter preferences.");
            var p=wire.Split('|');
            if(p.Length!=4||!long.TryParse(p[0],NumberStyles.None,CultureInfo.InvariantCulture,out var next)||next<0||next>DateTime.UtcNow.AddMinutes(5).Ticks||!Guid.TryParseExact(p[1],"N",out _)||(p[2]!="0"&&p[2]!="1")||(p[3]!="0"&&p[3]!="1"))throw new InvalidDataException("Invalid filter preferences.");
            lock(gate)
            {
                if(next<revision||(next==revision&&string.CompareOrdinal(p[1],edit)<=0))return false;
                revision=next;edit=p[1];code=p[2]=="1";loaded=p[3]=="1";Save();return true;
            }
        }
        void Save()
        {
            if(string.IsNullOrEmpty(path))return;
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))??throw new IOException("Missing preferences directory."));
            var temp=path+".tmp";File.WriteAllText(temp,Wire);
            if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);
        }
    }
}
