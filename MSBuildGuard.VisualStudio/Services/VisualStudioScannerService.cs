using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using MSBuildGuard.Core;
using MSBuildGuard.VisualStudio.Options;
using MSBuildGuard.Core.Policy;
using MSBuildGuard.Core.Scanning;
using MSBuildGuard.Core.Trust;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Provides scan operations for Visual Studio commands and tool windows.
	/// </summary>
	internal sealed class VisualStudioScannerService
	{
		private readonly MsBuildScanner scanner;
		private readonly MSBuildGuardPackage package;
		private readonly MSBuildGuard.VisualStudio.Options.MSBuildGuardOptionsSnapshot options;

		/// <summary>
		/// Initializes a new instance of the <see cref="VisualStudioScannerService"/> class.
		/// </summary>
		/// <param name="package">Owning package.</param>
		public VisualStudioScannerService(MSBuildGuardPackage package)
		{
			this.package = package;
			this.options = this.package.JoinableTaskFactory.Run(async delegate
			{
				return await this.package.GetOptionsSnapshotAsync(this.package.DisposalToken).ConfigureAwait(false);
			});

			this.scanner = new MsBuildScanner(
				fileSystem: null,
				activityLogger: this.LogActivity,
				msBuildExtensions: SplitList(this.options.FileTypesToScan),
				processCreationIndicators: SplitList(this.options.ProcessCreationIndicators),
				reflectionInteropIndicators: SplitList(this.options.ReflectionInteropIndicators),
				additionalBlockedAssemblies: SplitList(this.options.AdditionalBlockedAssemblies));
		}

		/// <summary>
		/// Splits a semicolon-delimited list from the options page into an array of strings, trimming whitespace and ignoring empty entries.
		/// </summary>
		/// <param name="value"></param>
		/// <returns></returns>
		private static IEnumerable<string> SplitList(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				return Array.Empty<string>();
			}

			var parts = value.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

			return parts;
		}

		/// <summary>
		/// Logs activity messages to the Visual Studio output window using the package's UI feedback service.
		/// </summary>
		/// <param name="message"></param>
		private void LogActivity(string message)
		{
			this.package.JoinableTaskFactory.RunAsync(async delegate
			{
				await this.package.UiFeedbackService.WriteLineAsync(message, CancellationToken.None);
			}).FileAndForget(nameof(VisualStudioScannerService));
		}

		/// <summary>
		/// Scans the specified solution path using the shared scanner.
		/// </summary>
		/// <param name="solutionPath">The solution path to scan.</param>
		/// <param name="cancellationToken">Cancellation token for the operation.</param>
		/// <returns>A scan report.</returns>
		public async Task<ScanReport> ScanSolutionAsync(string solutionPath, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(solutionPath))
			{
				throw new ArgumentException("A solution path is required.", nameof(solutionPath));
			}

			var targetName = Path.GetFileName(solutionPath);
			await this.package.UiFeedbackService.WriteLineAsync($"Scan started: {solutionPath}", CancellationToken.None);
			await this.package.UiFeedbackService.StartProgressAsync($"Scanning {targetName}", CancellationToken.None);

			try
			{
				var report = await Task.Run(delegate
				{
					cancellationToken.ThrowIfCancellationRequested();

					return this.scanner.Scan(solutionPath, cancellationToken);
				}, cancellationToken);

				ApplyPolicyEvaluation(report, solutionPath);

				await this.package.UiFeedbackService.WriteLineAsync($"Scan completed: {solutionPath} ({report.Findings.Count} findings)", CancellationToken.None);
				await this.package.UiFeedbackService.CompleteProgressAsync($"Scan completed: {targetName}", CancellationToken.None);

				return report;
			}
			catch (OperationCanceledException)
			{
				await this.package.UiFeedbackService.WriteLineAsync($"Scan canceled: {solutionPath}", CancellationToken.None);
				await this.package.UiFeedbackService.CompleteProgressAsync($"Scan canceled: {targetName}", CancellationToken.None);
				throw;
			}
			catch (Exception ex)
			{
				await this.package.UiFeedbackService.WriteLineAsync($"Scan failed: {solutionPath} ({ex.Message})", CancellationToken.None);
				await this.package.UiFeedbackService.CompleteProgressAsync($"Scan failed: {targetName}", CancellationToken.None);
				throw;
			}
		}

		/// <summary>
		/// Applies policy evaluation to the scan report based on the solution's repository context and user trust decisions.
		/// </summary>
		/// <param name="report">The scan report.</param>
		/// <param name="solutionPath">The path to the solution.</param>
		private static void ApplyPolicyEvaluation(ScanReport report, string solutionPath)
		{
			var repositoryRoot = Path.GetDirectoryName(Path.GetFullPath(solutionPath));
			var policy = new PolicyStatusService().GetEffectivePolicy(repositoryRoot, solutionPath);
			var trustService = new TrustStoreService();
			var trustPath = trustService.GetDefaultUserTrustPath();
			var trustStore = trustService.Load(trustPath);
			var evaluator = new PolicyDecisionEvaluator();

			evaluator.Apply(report, policy, null, trustStore);
		}
	}
}
