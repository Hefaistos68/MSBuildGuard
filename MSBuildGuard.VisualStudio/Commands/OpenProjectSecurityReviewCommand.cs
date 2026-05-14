using System;
using System.ComponentModel.Design;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.Core;
using MSBuildGuard.VisualStudio;
using MSBuildGuard.VisualStudio.Services;
using Task = System.Threading.Tasks.Task;

namespace MSBuildGuard.VisualStudio.Commands
{
	/// <summary>
	/// Implements the command that opens the Project Security Review tool window.
	/// </summary>
	internal sealed class OpenProjectSecurityReviewCommand
	{
		private readonly MSBuildGuardPackage package;
		private readonly VisualStudioScannerService scannerService;

		/// <summary>
		/// Initializes a new instance of the <see cref="OpenProjectSecurityReviewCommand"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		/// <param name="commandService">Menu command service.</param>
		private OpenProjectSecurityReviewCommand(AsyncPackage package, OleMenuCommandService commandService)
		{
			this.package       = (MSBuildGuardPackage)package;
			this.scannerService = new VisualStudioScannerService(this.package);

			var menuCommandId = new CommandID(new Guid(PackageGuids.CommandSetString), PackageIds.OpenProjectReviewCommandId);
			var menuItem      = new OleMenuCommand(this.Execute, menuCommandId);

			menuItem.BeforeQueryStatus += this.OnBeforeQueryStatus;
			commandService.AddCommand(menuItem);

			var contextCommandId = new CommandID(new Guid(PackageGuids.CommandSetString), PackageIds.OpenProjectReviewContextCommandId);
			var contextMenuItem  = new OleMenuCommand(this.Execute, contextCommandId);

			contextMenuItem.BeforeQueryStatus += this.OnBeforeQueryStatus;
			commandService.AddCommand(contextMenuItem);
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

			_ = new OpenProjectSecurityReviewCommand(package, commandService);
		}

		/// <summary>
		/// Executes the command.
		/// </summary>
		/// <param name="sender">Command sender.</param>
		/// <param name="e">Event arguments.</param>
		private void Execute(object? sender, EventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				await this.ExecuteAsync().ConfigureAwait(false);
			}).FileAndForget(nameof(OpenProjectSecurityReviewCommand));
		}

		private void OnBeforeQueryStatus(object sender, EventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			if (sender is not OleMenuCommand menuCommand)
			{
				return;
			}

			menuCommand.Visible = true;
			menuCommand.Enabled = !string.IsNullOrWhiteSpace(SolutionExplorerProjectDiscoveryService.GetSelectedProjectPath());
		}

		private async Task ExecuteAsync()
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

			var projectPath = SolutionExplorerProjectDiscoveryService.GetSelectedProjectPath();

			if (!string.IsNullOrWhiteSpace(projectPath) && File.Exists(projectPath))
			{
				var selectedProjectPath = projectPath!;
				var report              = await this.scannerService.ScanSolutionAsync(selectedProjectPath, this.package.DisposalToken);

				this.package.UpdateLatestScanReport(report);
				await this.package.ShowProjectSecurityReviewAsync(selectedProjectPath, report);
				return;
			}

			await this.package.ShowProjectSecurityReviewAsync(null, null);
		}

	}
}
