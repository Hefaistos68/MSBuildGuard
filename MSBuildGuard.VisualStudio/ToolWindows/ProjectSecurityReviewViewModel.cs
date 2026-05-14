using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// View model for the Project Security Review tool window.
	/// </summary>
	public sealed class ProjectSecurityReviewViewModel : INotifyPropertyChanged
	{
		private FindingViewModel? selectedFinding;

		/// <summary>
		/// Initializes a new instance of the <see cref="ProjectSecurityReviewViewModel"/> class.
		/// </summary>
		public ProjectSecurityReviewViewModel()
		{
			this.Findings = new ObservableCollection<FindingViewModel>();
			this.Summary  = new ScanSummaryViewModel();
		}

		/// <summary>
		/// Occurs when a property value changes.
		/// </summary>
		public event PropertyChangedEventHandler? PropertyChanged;

		/// <summary>
		/// Gets findings displayed in the grid.
		/// </summary>
		public ObservableCollection<FindingViewModel> Findings { get; }

		/// <summary>
		/// Gets scan summary data.
		/// </summary>
		public ScanSummaryViewModel Summary { get; }

		/// <summary>
		/// Gets or sets the currently selected finding.
		/// </summary>
		public FindingViewModel? SelectedFinding
		{
			get => this.selectedFinding;
			set
			{
				if (ReferenceEquals(this.selectedFinding, value))
				{
					return;
				}

				this.selectedFinding = value;
				this.OnPropertyChanged();
				this.OnPropertyChanged(nameof(this.ReasoningText));
			}
		}

		/// <summary>
		/// Gets the reasoning text for the currently selected finding.
		/// </summary>
		public string ReasoningText
		{
			get
			{
				return this.selectedFinding?.Reasoning ?? string.Empty;
			}
		}

		/// <summary>
		/// Gets the current target path.
		/// </summary>
		public string TargetPath
		{
			get
			{
				return this.Summary.TargetPath;
			}
		}

		/// <summary>
		/// Gets the current source target path.
		/// </summary>
		public string CurrentTargetPath { get; private set; } = string.Empty;

		/// <summary>
		/// Gets the current risk score.
		/// </summary>
		public int RiskScore
		{
			get
			{
				return this.Summary.RiskScore;
			}
		}

		/// <summary>
		/// Gets the current recommended action text.
		/// </summary>
		public string RecommendedAction
		{
			get
			{
				return this.Summary.RecommendedAction;
			}
		}

		/// <summary>
		/// Loads scan results into the view model.
		/// </summary>
		/// <param name="projectPath">The scanned project file path.</param>
		/// <param name="report">The scan report.</param>
		public void LoadReport(string projectPath, ScanReport report)
		{
			var trustStoreService = new TrustStoreService();
			var trustStore = trustStoreService.Load(trustStoreService.GetDefaultUserTrustPath());

			this.Findings.Clear();

			foreach (var finding in report.Findings)
			{
				var fileRecord = report.FilesScanned.FirstOrDefault(item => string.Equals(item.Path, finding.FilePath, System.StringComparison.OrdinalIgnoreCase));
				var isTrusted = !string.IsNullOrWhiteSpace(finding.Fingerprint) &&
					fileRecord != null &&
					trustStoreService.IsFindingApproved(trustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile);

				var isApprovedByAssembly = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion) &&
					trustStoreService.IsFindingApprovedByAssembly(trustStore, finding.PackageId, finding.PackageVersion);

				var owningAssembly = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion)
					? $"{finding.PackageId}@{finding.PackageVersion}"
					: string.Empty;

				this.Findings.Add(new FindingViewModel
				{
					Severity                    = finding.Severity.ToString(),
					RuleId                      = finding.Id,
					Title                       = finding.Title,
					FilePath                    = finding.FilePath,
					Line                        = finding.StartLine,
					Fingerprint                 = finding.Fingerprint,
					PolicyAction                = string.Equals(finding.Id, "MBG000", System.StringComparison.OrdinalIgnoreCase) ? "Trusted" : finding.PolicyAction.ToString(),
					IsTrusted                   = string.Equals(finding.Id, "MBG000", System.StringComparison.OrdinalIgnoreCase) || isTrusted || isApprovedByAssembly,
					IsInTrustStore              = isTrusted,
					IsNewComparedWithBaseline   = finding.IsNewComparedWithBaseline,
					OwningAssembly              = owningAssembly,
					Reasoning                   = FindingViewModel.BuildReasoning(finding, isTrusted || isApprovedByAssembly)
				});
			}

			this.CurrentTargetPath         = string.IsNullOrWhiteSpace(projectPath) ? report.Target.TargetPath : projectPath;
			this.Summary.TargetPath        = this.CurrentTargetPath;
			this.Summary.RiskScore         = report.RiskScore;
			this.Summary.RecommendedAction = report.RecommendedAction.ToString();
			this.Summary.FilesScanned      = report.FilesScanned.Count;
			this.Summary.FindingsCount     = report.Findings.Count;
			this.Summary.HasTargetLoaded   = !string.IsNullOrWhiteSpace(this.CurrentTargetPath);
		}

		/// <summary>
		/// Clears report data and marks target as not loaded.
		/// </summary>
		public void LoadEmpty()
		{
			this.Findings.Clear();
			this.SelectedFinding           = null;
			this.CurrentTargetPath         = string.Empty;
			this.Summary.TargetPath        = "No scan loaded";
			this.Summary.RiskScore         = 0;
			this.Summary.RecommendedAction = "Unknown";
			this.Summary.FilesScanned      = 0;
			this.Summary.FindingsCount     = 0;
			this.Summary.HasTargetLoaded   = false;
		}

		/// <summary>
		/// Displays the trust assembly dialog and adds the assembly to the trust store if confirmed.
		/// </summary>
		/// <param name="finding">The finding whose owning assembly will be trusted.</param>
		public async Task TrustAssemblyAsync(FindingViewModel finding)
		{
			if (finding == null)
			{
				return;
			}

			var owningAssembly = finding.OwningAssembly;

			if (string.IsNullOrWhiteSpace(owningAssembly))
			{
				return;
			}

			var parts = owningAssembly.Split('@');

			if (parts.Length != 2)
			{
				return;
			}

			var assemblyName    = parts[0];
			var assemblyVersion = parts[1];
			var trustStorePath  = new TrustStoreService().GetDefaultUserTrustPath();
			var dialog          = new TrustAssemblyDialog
			{
				Owner            = Application.Current.MainWindow,
				WindowStartupLocation = System.Windows.WindowStartupLocation.CenterOwner,
				AssemblyName     = assemblyName,
				AssemblyVersion  = assemblyVersion,
				AssemblyPath     = finding.FilePath
			};

			var result = dialog.ShowDialog();

			if (result != true)
			{
				return;
			}

			var trustStoreService = new TrustStoreService();
			var userSid           = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";
			var reason            = !string.IsNullOrWhiteSpace(dialog.TrustReason)
				? dialog.TrustReason
				: $"Assembly trusted from Visual Studio project review on {System.DateTime.UtcNow:O}";

			trustStoreService.AddAssemblyTrust(trustStorePath, assemblyName, assemblyVersion, reason, userSid);

			if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
			{
				await package.RescanProjectSecurityReviewAsync();
			}
		}

		/// <summary>
		/// Removes an assembly from the trust store.
		/// </summary>
		/// <param name="finding">The finding whose owning assembly will be untrusted.</param>
		public async Task UntrustAssemblyAsync(FindingViewModel finding)
		{
			if (finding == null)
			{
				return;
			}

			var owningAssembly = finding.OwningAssembly;

			if (string.IsNullOrWhiteSpace(owningAssembly))
			{
				return;
			}

			var parts = owningAssembly.Split('@');

			if (parts.Length != 2)
			{
				return;
			}

			var assemblyName    = parts[0];
			var assemblyVersion = parts[1];
			var result          = MessageBox.Show(
				$"Are you sure you want to remove trust for assembly '{assemblyName}' version '{assemblyVersion}'?\n\nFindings from this assembly will need to be approved individually.",
				"Untrust Assembly",
				MessageBoxButton.OKCancel,
				MessageBoxImage.Question);

			if (result != MessageBoxResult.OK)
			{
				return;
			}

			var trustStorePath    = new TrustStoreService().GetDefaultUserTrustPath();
			var trustStoreService = new TrustStoreService();
			var userSid           = WindowsIdentity.GetCurrent()?.User?.Value ?? "Unknown";

			trustStoreService.RemoveAssemblyTrust(trustStorePath, assemblyName, assemblyVersion, "Assembly untrusted from Visual Studio project review", userSid);

			if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
			{
				await package.RescanProjectSecurityReviewAsync();
			}
		}

		/// <summary>
		/// Raises the <see cref="PropertyChanged"/> event.
		/// </summary>
		/// <param name="propertyName">Name of the property that changed.</param>
		private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
		{
			this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		}
	}
}
