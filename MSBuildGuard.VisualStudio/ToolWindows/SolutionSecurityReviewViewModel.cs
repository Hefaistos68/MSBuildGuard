using System;
using System.Collections.Generic;
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
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// View model for the Solution Security Review tool window.
	/// </summary>
	public sealed class SolutionSecurityReviewViewModel : INotifyPropertyChanged
	{
		/// <summary>Sentinel path value representing the "All" project option.</summary>
		private const string AllProjectsPath = "__ALL__";

		/// <summary>Full flat list of all findings loaded from the last scan report.</summary>
		private readonly List<FindingViewModel> allFindings;

		/// <summary>Backing field for <see cref="SelectedProject"/>.</summary>
		private SolutionProjectOptionViewModel? selectedProject;

		/// <summary>Backing field for <see cref="SelectedFinding"/>.</summary>
		private FindingViewModel? selectedFinding;

		/// <summary>Backing field for <see cref="OnlyUntrustedIssues"/>.</summary>
		private bool onlyUntrustedIssues;

		/// <summary>Solution-level active risk score cached from the last loaded report.</summary>
		private int solutionRiskScore;

		/// <summary>Solution-level trusted risk score cached from the last loaded report.</summary>
		private int solutionTrustedRiskScore;

		/// <summary>Solution-level recommended action cached from the last loaded report.</summary>
		private string solutionRecommendedAction = string.Empty;

		/// <summary>
		/// Initializes a new instance of the <see cref="SolutionSecurityReviewViewModel"/> class.
		/// </summary>
		public SolutionSecurityReviewViewModel()
		{
			this.allFindings = new List<FindingViewModel>();
			this.Findings = new ObservableCollection<FindingViewModel>();
			this.Summary = new ScanSummaryViewModel();
			this.ProjectOptions = new ObservableCollection<SolutionProjectOptionViewModel>();
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
		/// Gets summary values.
		/// </summary>
		public ScanSummaryViewModel Summary { get; }

		/// <summary>
		/// Gets project options for selection.
		/// </summary>
		public ObservableCollection<SolutionProjectOptionViewModel> ProjectOptions { get; }

		/// <summary>
		/// Gets the current source target path.
		/// </summary>
		public string CurrentTargetPath { get; private set; } = string.Empty;

		/// <summary>
		/// Gets or sets currently selected project option.
		/// </summary>
		public SolutionProjectOptionViewModel? SelectedProject
		{
			get
			{
				return this.selectedProject;
			}
			set
			{
				if (ReferenceEquals(this.selectedProject, value))
				{
					return;
				}

				this.selectedProject = value;
				this.ApplyFilter();
				this.OnPropertyChanged();
			}
		}

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
		/// Gets or sets a value indicating whether only untrusted issues should be displayed.
		/// </summary>
		public bool OnlyUntrustedIssues
		{
			get
			{
				return this.onlyUntrustedIssues;
			}
			set
			{
				if (this.onlyUntrustedIssues == value)
				{
					return;
				}

				this.onlyUntrustedIssues = value;
				this.ApplyFilter();
				this.OnPropertyChanged();
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
		/// Loads a scan report and prepares project filtering options.
		/// </summary>
		/// <param name="solutionPath">The scanned solution path.</param>
		/// <param name="report">The scan report.</param>
		/// <param name="loadedProjectPaths">Project paths currently loaded in Solution Explorer.</param>
		public void LoadReport(string solutionPath, ScanReport report, IReadOnlyCollection<string>? loadedProjectPaths)
		{
			var previousSelectedPath = this.selectedProject?.Path;
			var trustStoreService = new TrustStoreService();
			var trustStore = trustStoreService.Load(trustStoreService.GetDefaultUserTrustPath());
			this.CurrentTargetPath = solutionPath;
			this.allFindings.Clear();

			// Cache resolved signatures per package to avoid redundant disk reads when multiple
			// findings originate from the same package.
			var hasSignerTrusts = trustStore.Decisions.Any(d => d.ScopeKind == MSBuildGuard.Core.Trust.TrustDecisionScopeKind.Signer);
			var signatureCache = new Dictionary<string, AssemblySignatureInfo>(StringComparer.OrdinalIgnoreCase);

			foreach (var finding in report.Findings)
			{
				var fileRecord = report.FilesScanned.FirstOrDefault(item => string.Equals(item.Path, finding.FilePath, StringComparison.OrdinalIgnoreCase));
				var isTrusted = !string.IsNullOrWhiteSpace(finding.Fingerprint) &&
					fileRecord != null &&
					trustStoreService.IsFindingApproved(trustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile);

				var isApprovedByAssembly = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion) &&
					trustStoreService.IsFindingApprovedByAssembly(trustStore, finding.PackageId, finding.PackageVersion);

				var isApprovedBySigner = false;

				if (hasSignerTrusts && !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion))
				{
					var cacheKey = $"{finding.PackageId}@{finding.PackageVersion}";

					if (!signatureCache.TryGetValue(cacheKey, out var signature))
					{
						var dllPath = Services.AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(finding.PackageId, finding.PackageVersion);
						signature = new Services.AssemblySignatureService().ReadSignature(dllPath);
						signatureCache[cacheKey] = signature;
					}

					if (signature.IsSignatureValid && (!string.IsNullOrWhiteSpace(signature.Thumbprint) || !string.IsNullOrWhiteSpace(signature.Subject)))
					{
						isApprovedBySigner = trustStoreService.IsSignerTrusted(trustStore, signature.Thumbprint, signature.Subject, signature.Issuer, signature.SerialNumber);
					}
				}

				var owningAssembly = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion)
					? $"{finding.PackageId}@{finding.PackageVersion}"
					: string.Empty;

				var isEffectivelyTrusted = isTrusted || isApprovedByAssembly || isApprovedBySigner;

				this.allFindings.Add(new FindingViewModel
				{
					Severity                  = finding.Severity.ToString(),
					RuleId                    = finding.Id,
					Title                     = finding.Title,
					FilePath                  = finding.FilePath,
					NuGetAssetPath            = finding.NuGetAssetPath,
					PackageId                 = finding.PackageId,
					PackageVersion            = finding.PackageVersion,
					IntroducedViaProject      = finding.IntroducedViaProject,
					Line                      = finding.StartLine,
					Fingerprint               = finding.Fingerprint,
					PolicyAction              = string.Equals(finding.Id, "MBG000", StringComparison.OrdinalIgnoreCase) ? "Trusted" : finding.PolicyAction.ToString(),
					IsTrusted                 = string.Equals(finding.Id, "MBG000", StringComparison.OrdinalIgnoreCase) || isEffectivelyTrusted,
					IsInTrustStore            = isTrusted,
					OwningAssembly            = owningAssembly,
					IsNewComparedWithBaseline = finding.IsNewComparedWithBaseline,
					Reasoning                 = FindingViewModel.BuildReasoning(finding, isEffectivelyTrusted)
				});
			}

			ComputeRiskScores(this.allFindings, out var solutionActiveRiskScore, out var solutionTrustedRiskScore);

			this.BuildProjectOptions(solutionPath, report, previousSelectedPath, loadedProjectPaths);
			this.solutionRiskScore         = solutionActiveRiskScore;
			this.solutionTrustedRiskScore  = solutionTrustedRiskScore;
			this.solutionRecommendedAction = MapRecommendedAction(solutionActiveRiskScore).ToString();
			this.Summary.TargetPath        = solutionPath;
			this.Summary.RiskScore         = solutionActiveRiskScore;
			this.Summary.TrustedRiskScore  = solutionTrustedRiskScore;
			this.Summary.RecommendedAction = this.solutionRecommendedAction;
			this.Summary.FilesScanned      = report.FilesScanned.Count;
			this.Summary.FindingsCount     = report.Findings.Count;
			this.Summary.HasTargetLoaded   = !string.IsNullOrWhiteSpace(solutionPath);
			this.ApplyFilter();
		}

		/// <summary>
		/// Clears report data and marks target as not loaded.
		/// </summary>
		public void LoadEmpty()
		{
			this.allFindings.Clear();
			this.Findings.Clear();
			this.ProjectOptions.Clear();
			this.selectedProject          = null;
			this.SelectedFinding          = null;
			this.CurrentTargetPath         = string.Empty;
			this.solutionRiskScore          = 0;
			this.solutionTrustedRiskScore   = 0;
			this.solutionRecommendedAction  = "Unknown";
			this.Summary.TargetPath         = "No scan loaded";
			this.Summary.RiskScore          = 0;
			this.Summary.TrustedRiskScore   = 0;
			this.Summary.RecommendedAction  = "Unknown";
			this.Summary.FilesScanned       = 0;
			this.Summary.FindingsCount      = 0;
			this.Summary.HasTargetLoaded    = false;
			this.OnPropertyChanged(nameof(this.SelectedProject));
		}

		/// <summary>
		/// Rebuilds the project dropdown options from loaded project paths and scanned files,
		/// then restores the previously selected project when possible.
		/// </summary>
		/// <param name="solutionPath">The currently open solution path.</param>
		/// <param name="report">The scan report used as a fallback source of project paths.</param>
		/// <param name="previousSelectedPath">The project path that was selected before the reload.</param>
		/// <param name="loadedProjectPaths">Project paths currently loaded in Solution Explorer.</param>
		private void BuildProjectOptions(string solutionPath, ScanReport report, string? previousSelectedPath, IReadOnlyCollection<string>? loadedProjectPaths)
		{
			this.ProjectOptions.Clear();
			this.ProjectOptions.Add(new SolutionProjectOptionViewModel
			{
				Name = "All",
				Path = AllProjectsPath
			});

			var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

			if (loadedProjectPaths != null)
			{
				foreach (var projectPath in loadedProjectPaths)
				{
					if (string.IsNullOrWhiteSpace(projectPath) || !seen.Add(projectPath))
					{
						continue;
					}

					this.ProjectOptions.Add(new SolutionProjectOptionViewModel
					{
						Name = Path.GetFileNameWithoutExtension(projectPath),
						Path = projectPath
					});
				}
			}

			if (this.ProjectOptions.Count == 1)
			{
				foreach (var file in report.FilesScanned)
				{
					if (file.FileKind != MsBuildFileKind.Project)
					{
						continue;
					}

					if (string.IsNullOrWhiteSpace(file.Path) || !seen.Add(file.Path))
					{
						continue;
					}

					this.ProjectOptions.Add(new SolutionProjectOptionViewModel
					{
						Name = Path.GetFileNameWithoutExtension(file.Path),
						Path = file.Path
					});
				}
			}

			if (this.ProjectOptions.Count == 1)
			{
				this.ProjectOptions.Add(new SolutionProjectOptionViewModel
				{
					Name = Path.GetFileNameWithoutExtension(solutionPath),
					Path = solutionPath
				});
			}

			if (!string.IsNullOrWhiteSpace(previousSelectedPath))
			{
				this.selectedProject = this.ProjectOptions.FirstOrDefault(option => string.Equals(option.Path, previousSelectedPath, StringComparison.OrdinalIgnoreCase));
			}

			if (this.selectedProject == null)
			{
				this.selectedProject = this.ProjectOptions.FirstOrDefault();
			}

			this.OnPropertyChanged(nameof(this.SelectedProject));
		}

		/// <summary>
		/// Filters <see cref="Findings"/> to the currently selected project and updates the
		/// <see cref="Summary"/> with target path, risk score, and recommended action for that scope.
		/// When a specific project has no matching findings a synthetic MBG000 row is added.
		/// </summary>
		private void ApplyFilter()
		{
			this.Findings.Clear();

			if (this.selectedProject == null || string.Equals(this.selectedProject.Path, AllProjectsPath, StringComparison.OrdinalIgnoreCase))
			{
				foreach (var finding in this.allFindings)
				{
					if (this.onlyUntrustedIssues && finding.IsTrusted)
					{
						continue;
					}

					this.Findings.Add(finding);
				}

				this.Summary.TargetPath        = this.CurrentTargetPath;
				this.Summary.RiskScore         = this.solutionRiskScore;
				this.Summary.TrustedRiskScore  = this.solutionTrustedRiskScore;
				this.Summary.RecommendedAction = this.solutionRecommendedAction;
				this.Summary.FindingsCount     = this.Findings.Count;
				return;
			}

			var selectedProjectPath = this.selectedProject.Path;
			var projectDirectory = Path.GetDirectoryName(selectedProjectPath) ?? string.Empty;

			foreach (var finding in this.allFindings)
			{
				if (!BelongsToProject(finding, selectedProjectPath, projectDirectory))
				{
					continue;
				}

				if (this.onlyUntrustedIssues && finding.IsTrusted)
				{
					continue;
				}

				this.Findings.Add(finding);
			}

			if (this.Findings.Count == 0)
			{
				this.Findings.Add(new FindingViewModel
				{
					Severity   = FindingSeverity.None.ToString(),
					RuleId     = "MBG000",
					Title      = "No issues detected",
					FilePath   = selectedProjectPath,
					Line       = 1,
					PolicyAction = "Trusted",
					IsTrusted  = true,
					Reasoning  = "No findings were detected for this project."
				});
			}

			ComputeRiskScores(this.Findings, out var projectRiskScore, out var projectTrustedRiskScore);
			this.Summary.TargetPath        = selectedProjectPath;
			this.Summary.RiskScore         = projectRiskScore;
			this.Summary.TrustedRiskScore  = projectTrustedRiskScore;
			this.Summary.RecommendedAction = MapRecommendedAction(projectRiskScore).ToString();
			this.Summary.FindingsCount     = this.Findings.Count;
		}

		/// <summary>
		/// Computes active and trusted risk totals from findings using severity weights
		/// Low=5, Medium=20, High=50, Critical=100.
		/// </summary>
		/// <param name="findings">The findings to score.</param>
		/// <param name="activeRiskScore">Calculated active risk score.</param>
		/// <param name="trustedRiskScore">Calculated trusted risk score.</param>
		private static void ComputeRiskScores(IEnumerable<FindingViewModel> findings, out int activeRiskScore, out int trustedRiskScore)
		{
			activeRiskScore = 0;
			trustedRiskScore = 0;

			foreach (var finding in findings)
			{
				var risk = GetSeverityRisk(finding.Severity);

				if (finding.IsTrusted)
				{
					trustedRiskScore += risk;
					continue;
				}

				activeRiskScore += risk;
			}
		}

		/// <summary>
		/// Maps severity text to weighted risk contribution.
		/// </summary>
		/// <param name="severityText">Severity text value.</param>
		/// <returns>Weighted risk contribution.</returns>
		private static int GetSeverityRisk(string severityText)
		{
			if (!Enum.TryParse<FindingSeverity>(severityText, out var severity))
			{
				return 0;
			}

			switch (severity)
			{
				case FindingSeverity.Low:
					return 5;
				case FindingSeverity.Medium:
					return 20;
				case FindingSeverity.High:
					return 50;
				case FindingSeverity.Critical:
					return 100;
				default:
					return 0;
			}
		}

		/// <summary>
		/// Maps an aggregate risk score to a <see cref="RecommendedAction"/> using the same
		/// thresholds as the Core scanner: ≥100 Block, ≥50 RequireApproval, ≥20 Warn, else Allow.
		/// </summary>
		/// <param name="riskScore">The aggregate risk score.</param>
		/// <returns>The recommended action for the score band.</returns>
		private static RecommendedAction MapRecommendedAction(int riskScore)
		{
			if (riskScore >= 100)
			{
				return RecommendedAction.Block;
			}

			if (riskScore >= 50)
			{
				return RecommendedAction.RequireApproval;
			}

			if (riskScore >= 20)
			{
				return RecommendedAction.Warn;
			}

			return RecommendedAction.Allow;
		}

		/// <summary>
		/// Determines whether a finding belongs to the specified project.
		/// Package-sourced findings are matched via <see cref="FindingViewModel.IntroducedViaProject"/>;
		/// file-level findings are matched by exact project file path or by a path-separator-bounded
		/// directory prefix check for files inside the project directory.
		/// </summary>
		/// <param name="finding">The finding to test.</param>
		/// <param name="projectPath">The absolute path of the project file.</param>
		/// <param name="projectDirectory">The directory containing the project file.</param>
		/// <returns><c>true</c> when the finding belongs to the project; otherwise <c>false</c>.</returns>
		private static bool BelongsToProject(FindingViewModel finding, string projectPath, string projectDirectory)
		{
			// Package-sourced findings carry the originating project path directly.
			if (!string.IsNullOrWhiteSpace(finding.IntroducedViaProject))
			{
				return string.Equals(finding.IntroducedViaProject, projectPath, StringComparison.OrdinalIgnoreCase);
			}

			// File-level findings: the finding file is the project file itself.
			if (string.Equals(finding.FilePath, projectPath, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			// Findings in files under the project directory (e.g. imported .props/.targets).
			if (!string.IsNullOrWhiteSpace(projectDirectory))
			{
				var dir = projectDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
				var filePath = finding.FilePath;

				if (filePath.Length > dir.Length
					&& filePath.StartsWith(dir, StringComparison.OrdinalIgnoreCase)
					&& (filePath[dir.Length] == Path.DirectorySeparatorChar || filePath[dir.Length] == Path.AltDirectorySeparatorChar))
				{
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// Raises the <see cref="PropertyChanged"/> event for the specified property.
		/// </summary>
		/// <param name="propertyName">Name of the changed property; supplied automatically by the compiler.</param>
		private void OnPropertyChanged([CallerMemberName] string propertyName = "")
		{
			this.PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
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
			var assemblyPath    = MSBuildGuard.VisualStudio.Services.AssemblySignatureService.ResolveAssemblyFilePath(finding.FilePath);

			if (!string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion))
			{
				var packageAssemblyPath = MSBuildGuard.VisualStudio.Services.AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(finding.PackageId, finding.PackageVersion);

				if (!string.IsNullOrWhiteSpace(packageAssemblyPath))
				{
					assemblyPath = packageAssemblyPath;
				}
			}

			var dialog          = new TrustAssemblyDialog
			{
				Owner            = Application.Current.MainWindow,
				WindowStartupLocation = System.Windows.WindowStartupLocation.CenterOwner,
				AssemblyName     = assemblyName,
					AssemblyVersion  = assemblyVersion,
					AssemblyPath     = assemblyPath
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
				: $"Assembly trusted from Visual Studio solution review on {System.DateTime.UtcNow:O}";

			trustStoreService.AddAssemblyTrust(
				trustStorePath,
				assemblyName,
				assemblyVersion,
				reason,
				userSid,
				dialog.AssemblySigner,
				dialog.AssemblyIssuer,
				dialog.AssemblySubject);

			if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
			{
				await package.RescanSolutionSecurityReviewAsync();
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

			trustStoreService.RemoveAssemblyTrust(trustStorePath, assemblyName, assemblyVersion, "Assembly untrusted from Visual Studio solution review", userSid);

			if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
			{
				await package.RescanSolutionSecurityReviewAsync();
			}
		}
	}
}
