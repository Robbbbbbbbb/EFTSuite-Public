// EFTHelper, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// EFTHelper.Program
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows.Forms;

internal static class Program
{
	[STAThread]
	private static void Main(string[] args)
	{
		try {
			var lp = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "efthelper_diag.txt");
			var sw = new System.IO.StreamWriter(lp, append: false) { AutoFlush = true };
			Console.SetOut(sw); Console.SetError(sw);
		} catch {}
		Application.EnableVisualStyles();
		Application.SetCompatibleTextRenderingDefault(defaultValue: false);
		if (!IsRunAsAdmin())
		{
			if (MessageBox.Show("EFT Helper requires Administrator privileges to function correctly (binding to network ports).\n\nWould you like to relaunch as Administrator?", "Administrator Privileges Required", MessageBoxButtons.YesNo, MessageBoxIcon.Exclamation) == DialogResult.Yes)
			{
				RelaunchAsAdmin();
			}
		}
		else
		{
			Application.Run(new MainForm());
		}
	}

	private static bool IsRunAsAdmin()
	{
		try
		{
			return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
		}
		catch
		{
			return false;
		}
	}

	private static void RelaunchAsAdmin()
	{
		ProcessStartInfo startInfo = new ProcessStartInfo();
		startInfo.UseShellExecute = true;
		startInfo.WorkingDirectory = Environment.CurrentDirectory;
		startInfo.FileName = Application.ExecutablePath;
		startInfo.Verb = "runas";
		try
		{
			Process.Start(startInfo);
		}
		catch (Win32Exception)
		{
			return;
		}
		Application.Exit();
	}
}
