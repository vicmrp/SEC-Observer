namespace Observe;

public sealed class SetupDialog : Form
{
    readonly TextBox exe=new(){Dock=DockStyle.Fill};readonly TextBox xml=new(){Dock=DockStyle.Fill};
    readonly CheckBox replace=new(){Text="Replace the existing Sysmon configuration. The XML above is its known original configuration for restoration.",AutoSize=true,MaximumSize=new Size(690,0)};
    readonly CheckBox license=new(){Text="I have reviewed and accept the Microsoft Sysmon license (required for a new installation).",AutoSize=true,MaximumSize=new Size(690,0)};
    public string Executable=>exe.Text;public string RestoreXml=>xml.Text;public bool ReplaceExisting=>replace.Checked;public bool AcceptLicense=>license.Checked;
    public SetupDialog()
    {
        Text="Configure forensic sensors";Size=new Size(790,690);MinimumSize=new Size(790,690);StartPosition=FormStartPosition.CenterParent;Font=new Font("Segoe UI",10);
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,Padding=new Padding(22),AutoScroll=true};Controls.Add(layout);
        void Add(Control c,int height){c.Dock=DockStyle.Top;c.Height=height;layout.RowStyles.Add(new RowStyle(SizeType.Absolute,height+12));layout.Controls.Add(c,0,layout.RowCount++);}
        Add(new Label{Text="Enable Windows forensic logging",Font=new Font("Segoe UI",20)},43);
        Add(new Label{Text="This will enable Sysmon process, network, file and registry events; PowerShell script and module logging; and 64 MB circular event logs. Scripts may contain sensitive data. Existing policy values are backed up before changes.",MaximumSize=new Size(690,0)},78);
        exe.Text=SensorSetup.SuggestedExecutable();xml.Text=Path.Combine(Path.GetDirectoryName(exe.Text)??"","sysmonconfig.xml");if(!File.Exists(xml.Text))xml.Text="";
        Add(new Label{Text="Microsoft-signed Sysmon executable"},24);Add(PathRow(exe,"Executables|*.exe"),34);
        Add(new Label{Text="Current/original Sysmon XML (required if Sysmon is already installed)"},24);Add(PathRow(xml,"Sysmon configuration|*.xml"),34);
        Add(replace,52);Add(license,45);
        var link=new LinkLabel{Text="Download Sysmon and review its license on Microsoft’s website",AutoSize=true};link.LinkClicked+=(_,_)=>System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"){UseShellExecute=true});Add(link,26);
        Add(new Label{Text="The app verifies the Microsoft signature before running Sysmon. Your original XML is needed because Sysmon’s current-configuration text output is not a restorable XML backup. Do not replace organization-managed settings.",MaximumSize=new Size(690,0)},67);
        var apply=new Button{Text="Configure sensors",DialogResult=DialogResult.OK,AutoSize=true,Padding=new Padding(14,6,14,6)};var cancel=new Button{Text="Cancel",DialogResult=DialogResult.Cancel,AutoSize=true,Padding=new Padding(14,6,14,6)};
        var buttons=new FlowLayoutPanel{FlowDirection=FlowDirection.RightToLeft};buttons.Controls.Add(apply);buttons.Controls.Add(cancel);Add(buttons,46);AcceptButton=apply;CancelButton=cancel;
    }
    Control PathRow(TextBox field,string filter)
    {
        var panel=new TableLayoutPanel{ColumnCount=2,Dock=DockStyle.Fill};panel.ColumnStyles.Add(new(SizeType.Percent,100));panel.ColumnStyles.Add(new(SizeType.Absolute,90));var browse=new Button{Text="Browse…",Dock=DockStyle.Fill};
        browse.Click+=(_,_)=>{using var dialog=new OpenFileDialog{Filter=filter};if(dialog.ShowDialog(this)==DialogResult.OK)field.Text=dialog.FileName;};panel.Controls.Add(field,0,0);panel.Controls.Add(browse,1,0);return panel;
    }
}
