using System;
using System.ComponentModel.Design;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Task = System.Threading.Tasks.Task;

namespace MSBuildGuard.VisualStudio.Commands
{
	/// <summary>
	/// Implements the scan solution command.
	/// </summary>
	internal sealed class ScanSolutionCommand
	{
		private readonly AsyncPackage package;

		/// <summary>
		/// Initializes a new instance of the <see cref="ScanSolutionCommand"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		/// <param name="commandService">Menu command service.</param>
		private ScanSolutionCommand(AsyncPackage package, OleMenuCommandService commandService)
		{
			this.package = package;

			var menuCommandId = new CommandID(new Guid(PackageGuids.CommandSetString), PackageIds.ScanSolutionCommandId);
			var menuItem      = new OleMenuCommand(this.Execute, menuCommandId);

			menuItem.BeforeQueryStatus += this.OnBeforeQueryStatus;
			commandService.AddCommand(menuItem);
		}

		/// <summary>
		/// Registers the command with Visual Studio.
		/// </summary>
		/// <param name="package">Owning package.</param>
		/// <returns>A task that completes when registration is done.</returns>
		public static async Task InitializeAsync(AsyncPackage package)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

			var commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;

			if (commandService == null)
			{
				return;
			}

			_ = new ScanSolutionCommand(package, commandService);
		}

		private void OnBeforeQueryStatus(object sender, EventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			if (sender is not OleMenuCommand menuCommand)
			{
				return;
			}

			menuCommand.Visible = true;
			menuCommand.Enabled = Services.SolutionDiscoveryService.HasOpenSolution();
		}

		/// <summary>
		/// Executes the command.
		/// </summary>
		/// <param name="sender">Command sender.</param>
		/// <param name="e">Event arguments.</param>
		private void Execute(object? sender, EventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			VsShellUtilities.ShowMessageBox(
				this.package,
				"Solution scanning will be wired in the scanner service step.",
				"MSBuild Guard",
				OLEMSGICON.OLEMSGICON_INFO,
				OLEMSGBUTTON.OLEMSGBUTTON_OK,
				OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
		}
	}
}
