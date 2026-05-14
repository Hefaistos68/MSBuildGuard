using System;
using System.ComponentModel.Design;
using System.IO;
using System.Threading.Tasks;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Baseline;
using Task = System.Threading.Tasks.Task;

namespace MSBuildGuard.VisualStudio.Commands
{
	/// <summary>
	/// Implements the create baseline command.
	/// </summary>
	internal sealed class CreateBaselineCommand
	{
		private readonly MSBuildGuardPackage package;

		/// <summary>
		/// Initializes a new instance of the <see cref="CreateBaselineCommand"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		/// <param name="commandService">Menu command service.</param>
		private CreateBaselineCommand(AsyncPackage package, OleMenuCommandService commandService)
		{
			this.package = (MSBuildGuardPackage)package;

			var menuCommandId = new CommandID(new Guid(PackageGuids.CommandSetString), PackageIds.CreateBaselineCommandId);
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

			_ = new CreateBaselineCommand(package, commandService);
		}

		/// <summary>
		/// Handles command execution.
		/// </summary>
		/// <param name="sender">Command sender.</param>
		/// <param name="e">Event arguments.</param>
		private void Execute(object? sender, EventArgs e)
		{
			ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
			{
				await this.ExecuteAsync().ConfigureAwait(false);
			}).FileAndForget(nameof(CreateBaselineCommand));
		}

		/// <summary>
		/// Updates command visibility and enablement state.
		/// </summary>
		/// <param name="sender">Command sender.</param>
		/// <param name="e">Event arguments.</param>
		private void OnBeforeQueryStatus(object sender, EventArgs e)
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			if (sender is not OleMenuCommand menuCommand)
			{
				return;
			}

			var hasOpenSolution = Services.SolutionDiscoveryService.HasOpenSolution();
			var report = this.package.LatestScanReport;
			var isGreen = report != null && report.RecommendedAction == RecommendedAction.Allow;

			menuCommand.Visible = true;
			menuCommand.Enabled = hasOpenSolution && isGreen;
		}

		private async Task ExecuteAsync()
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

			var report = this.package.LatestScanReport;

			if (report == null || report.RecommendedAction != RecommendedAction.Allow)
			{
				await this.package.UiFeedbackService.WriteLineAsync("Create Baseline is available only when project security is green.", this.package.DisposalToken);
				return;
			}

			var solutionPath = await Services.SolutionDiscoveryService.GetOpenSolutionPathAsync(this.package);

			if (string.IsNullOrWhiteSpace(solutionPath))
			{
				await this.package.UiFeedbackService.WriteLineAsync("Cannot create baseline because no solution is open.", this.package.DisposalToken);
				return;
			}

			var solutionDirectory = Path.GetDirectoryName(solutionPath);

			if (string.IsNullOrWhiteSpace(solutionDirectory))
			{
				await this.package.UiFeedbackService.WriteLineAsync("Cannot resolve solution directory for baseline creation.", this.package.DisposalToken);
				return;
			}

			var baselinePath = Path.Combine(solutionDirectory, ".msbuildguard", "baseline.json");

			if (File.Exists(baselinePath))
			{
				var overwriteResult = VsShellUtilities.ShowMessageBox(
					this.package,
					$"A baseline already exists at:{Environment.NewLine}{baselinePath}{Environment.NewLine}{Environment.NewLine}Do you want to overwrite it?",
					"MSBuild Guard",
					OLEMSGICON.OLEMSGICON_QUERY,
					OLEMSGBUTTON.OLEMSGBUTTON_YESNO,
					OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_SECOND);

				if (overwriteResult != (int)VSConstants.MessageBoxResult.IDYES)
				{
					await this.package.UiFeedbackService.WriteLineAsync("Create Baseline canceled by user.", this.package.DisposalToken);
					return;
				}
			}

			var baselineService = new BaselineService();
			var baseline = baselineService.CreateFromReport(report, "visualstudio", Environment.UserName);

			baselineService.Save(baselinePath, baseline);
			await this.package.UiFeedbackService.WriteLineAsync($"Baseline saved: {baselinePath}", this.package.DisposalToken);
		}
	}
}
