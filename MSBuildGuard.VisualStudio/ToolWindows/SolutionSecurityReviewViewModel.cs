using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using System.Xml.Linq;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.Services;
using Microsoft.VisualStudio.Settings;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Settings;

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
		/// Gets the solution-level effective risk score for the latest full solution scan.
		/// </summary>
		public int SolutionEffectiveRiskScore { get; private set; }

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
				ThreadHelper.ThrowIfNotOnUIThread();
				if (ReferenceEquals(this.selectedProject, value))
				{
					return;
				}

				this.selectedProject = value;

				// Read the setting for the newly selected scope, and notify the UI
				var path = this.selectedProject?.Path ?? AllProjectsPath;
				this.onlyUntrustedIssues = ReadOnlyUntrustedSetting(path);

				this.ApplyFilter();
				this.OnPropertyChanged();
				this.OnPropertyChanged(nameof(this.OnlyUntrustedIssues));
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
				ThreadHelper.ThrowIfNotOnUIThread();
				if (this.onlyUntrustedIssues == value)
				{
					return;
				}

				this.onlyUntrustedIssues = value;

				// Store the changed value at the scope level
				var path = this.selectedProject?.Path ?? AllProjectsPath;
				SaveOnlyUntrustedSetting(path, value);

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
			ThreadHelper.ThrowIfNotOnUIThread();
			var previousSelectedPath = this.selectedProject?.Path;
			var trustStoreService    = new TrustStoreService();
			var currentProjectPath   = this.selectedProject != null && !string.Equals(this.selectedProject.Path, AllProjectsPath, StringComparison.OrdinalIgnoreCase)
				? this.selectedProject.Path
				: null;
			var userTrustStore = trustStoreService.Load(trustStoreService.GetDefaultUserTrustPath());
			var solutionTrustStore = !string.IsNullOrWhiteSpace(solutionPath)
				? trustStoreService.Load(trustStoreService.GetSolutionTrustPath(solutionPath))
				: new TrustStoreDocument();
			var projectTrustStoreCache = new Dictionary<string, TrustStoreDocument>(StringComparer.OrdinalIgnoreCase);
			var trustStore = trustStoreService.LoadMergedTrustStore(trustStoreService.GetDefaultUserTrustPath(), solutionPath, currentProjectPath);
			this.CurrentTargetPath = solutionPath;
			this.allFindings.Clear();

			// Cache resolved signatures per package to avoid redundant disk reads when multiple
			// findings originate from the same package.
			var hasSignerTrusts = trustStore.Decisions.Any(d => d.ScopeKind == MSBuildGuard.Core.Trust.TrustDecisionScopeKind.Signer);
			var signatureCache = new Dictionary<string, AssemblySignatureInfo>(StringComparer.OrdinalIgnoreCase);

			foreach (var finding in report.Findings)
			{
				var fileRecord = report.FilesScanned.FirstOrDefault(item => string.Equals(item.Path, finding.FilePath, StringComparison.OrdinalIgnoreCase));
				var findingProjectPath = !string.IsNullOrWhiteSpace(finding.IntroducedViaProject) ? finding.IntroducedViaProject : string.Empty;
				var projectTrustStore  = (TrustStoreDocument?)null;


				if (!string.IsNullOrWhiteSpace(findingProjectPath))
				{
					var absoluteFindingProjectPath = Path.IsPathRooted(findingProjectPath)
						? Path.GetFullPath(findingProjectPath)
						: Path.GetFullPath(Path.Combine(Path.GetDirectoryName(solutionPath) ?? string.Empty, findingProjectPath));


					if (!projectTrustStoreCache.TryGetValue(absoluteFindingProjectPath, out projectTrustStore))
					{
						projectTrustStore = trustStoreService.Load(trustStoreService.GetProjectTrustPath(absoluteFindingProjectPath));
						projectTrustStoreCache[absoluteFindingProjectPath] = projectTrustStore;
					}
				}

				var issueTrustScopes = new List<string>();
				var assemblyTrustScopes = new List<string>();
				var signerTrustScopes = new List<string>();

				var isTrusted = false;

				if (!string.IsNullOrWhiteSpace(finding.Fingerprint) && fileRecord != null)
				{
					if (trustStoreService.IsFindingApproved(userTrustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile))
					{
						issueTrustScopes.Add("User");
					}

					if (trustStoreService.IsFindingApproved(solutionTrustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile))
					{
						issueTrustScopes.Add("Solution");
					}

					if (projectTrustStore != null && trustStoreService.IsFindingApproved(projectTrustStore, finding.Fingerprint, fileRecord.NormalizedSha256, report.Target.TrustContext, report.PolicyProfile))
					{
						issueTrustScopes.Add("Project");
					}

					isTrusted = issueTrustScopes.Count > 0;
				}

				var isApprovedByAssembly = false;

				if (!string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion))
				{
					if (trustStoreService.IsFindingApprovedByAssembly(userTrustStore, finding.PackageId, finding.PackageVersion))
					{
						assemblyTrustScopes.Add("User");
					}

					if (trustStoreService.IsFindingApprovedByAssembly(solutionTrustStore, finding.PackageId, finding.PackageVersion))
					{
						assemblyTrustScopes.Add("Solution");
					}

					if (projectTrustStore != null && trustStoreService.IsFindingApprovedByAssembly(projectTrustStore, finding.PackageId, finding.PackageVersion))
					{
						assemblyTrustScopes.Add("Project");
					}

					isApprovedByAssembly = assemblyTrustScopes.Count > 0;
				}

				var isApprovedBySigner = false;

				if (hasSignerTrusts && !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion))
				{
					var cacheKey = $"{finding.PackageId}@{finding.PackageVersion}";

					if (!signatureCache.TryGetValue(cacheKey, out var signature))
					{
						var dllPath = AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(finding.PackageId, finding.PackageVersion);
						signature = new AssemblySignatureService().ReadSignature(dllPath);
						signatureCache[cacheKey] = signature;
					}

					if (signature.IsSignatureValid && (!string.IsNullOrWhiteSpace(signature.Thumbprint) || !string.IsNullOrWhiteSpace(signature.Subject)))
					{
						if (trustStoreService.IsSignerTrusted(userTrustStore, signature.Thumbprint, signature.Subject, signature.Issuer, signature.SerialNumber))
						{
							signerTrustScopes.Add("User");
						}

						if (trustStoreService.IsSignerTrusted(solutionTrustStore, signature.Thumbprint, signature.Subject, signature.Issuer, signature.SerialNumber))
						{
							signerTrustScopes.Add("Solution");
						}

						if (projectTrustStore != null && trustStoreService.IsSignerTrusted(projectTrustStore, signature.Thumbprint, signature.Subject, signature.Issuer, signature.SerialNumber))
						{
							signerTrustScopes.Add("Project");
						}

						isApprovedBySigner = signerTrustScopes.Count > 0;
					}
				}

				var owningAssembly = !string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion)
					? $"{finding.PackageId}@{finding.PackageVersion}"
					: string.Empty;

				var trustStatusDetails = BuildTrustStatusDetails(issueTrustScopes, assemblyTrustScopes, signerTrustScopes);
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
					Reasoning                 = FindingViewModel.BuildReasoning(finding, isEffectivelyTrusted, trustStatusDetails)
				});
			}

			ComputeRiskScores(this.allFindings, out var solutionActiveRiskScore, out var solutionTrustedRiskScore);

			this.BuildProjectOptions(solutionPath, report, previousSelectedPath, loadedProjectPaths);
			this.solutionRiskScore         = solutionActiveRiskScore;
			this.solutionTrustedRiskScore  = solutionTrustedRiskScore;
			this.SolutionEffectiveRiskScore = solutionActiveRiskScore;
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
			this.SolutionEffectiveRiskScore = 0;
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
			ThreadHelper.ThrowIfNotOnUIThread();
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

					if (!IsBuildableProjectPath(projectPath))
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

			// Load the OnlyUntrustedIssues setting for the restored/selected scope
			var path = this.selectedProject?.Path ?? AllProjectsPath;
			this.onlyUntrustedIssues = ReadOnlyUntrustedSetting(path);

			this.OnPropertyChanged(nameof(this.SelectedProject));
			this.OnPropertyChanged(nameof(this.OnlyUntrustedIssues));
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

			var projectName = this.selectedProject.Name;


			foreach (var finding in this.allFindings)
			{
				if (!BelongsToProject(finding, projectName))
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
					FilePath   = this.selectedProject.Path,
					Line       = 1,
					PolicyAction = "Trusted",
					IsTrusted  = true,
					Reasoning  = "No findings were detected for this project."
				});
			}

			ComputeRiskScores(this.Findings, out var projectRiskScore, out var projectTrustedRiskScore);
			this.Summary.TargetPath        = this.selectedProject.Path;
			this.Summary.RiskScore         = projectRiskScore;
			this.Summary.TrustedRiskScore  = projectTrustedRiskScore;
			this.Summary.RecommendedAction = MapRecommendedAction(projectRiskScore).ToString();
			this.Summary.FindingsCount     = this.Findings.Count;
		}

		/// <summary>
		/// Builds a reasoning-friendly trust detail summary, including trust type and matching scope.
		/// </summary>
		/// <param name="issueTrustScopes">Matching scope names for issue trust.</param>
		/// <param name="assemblyTrustScopes">Matching scope names for assembly trust.</param>
		/// <param name="signerTrustScopes">Matching scope names for signer trust.</param>
		/// <returns>Concise trust detail string.</returns>
		private static string BuildTrustStatusDetails(IReadOnlyCollection<string> issueTrustScopes, IReadOnlyCollection<string> assemblyTrustScopes, IReadOnlyCollection<string> signerTrustScopes)
		{
			var parts = new List<string>();

			if (issueTrustScopes.Count > 0)
			{
				parts.Add($"issue trust ({string.Join("/", issueTrustScopes)})");
			}

			if (assemblyTrustScopes.Count > 0)
			{
				parts.Add($"assembly trust ({string.Join("/", assemblyTrustScopes)})");
			}

			if (signerTrustScopes.Count > 0)
			{
				parts.Add($"signer trust ({string.Join("/", signerTrustScopes)})");
			}

			return string.Join("; ", parts);
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
		/// Determines whether a finding belongs to the specified project by checking the "File" display column.
		/// </summary>
		/// <param name="finding">The finding to test.</param>
		/// <param name="projectName">The name of the selected project.</param>
		/// <returns><c>true</c> when the finding belongs to the project; otherwise <c>false</c>.</returns>
		private static bool BelongsToProject(FindingViewModel finding, string projectName)
		{
			if (string.IsNullOrWhiteSpace(projectName))
			{
				return false;
			}


			return finding.FilePathDisplay.IndexOf(projectName, StringComparison.OrdinalIgnoreCase) >= 0;
		}

		/// <summary>
		/// Determines whether the provided path points to a buildable project file.
		/// </summary>
		/// <param name="path">Project path candidate.</param>
		/// <returns><c>true</c> when the path has a known buildable project extension; otherwise <c>false</c>.</returns>
		private static bool IsBuildableProjectPath(string path)
		{
			if (string.IsNullOrWhiteSpace(path))
			{
				return false;
			}

			var extension = Path.GetExtension(path);

			return string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(extension, ".vbproj", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(extension, ".fsproj", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(extension, ".proj", StringComparison.OrdinalIgnoreCase);
		}

		/// <summary>
		/// Builds a lookup for non-buildable solution item names from SLN/SLNX content.
		/// </summary>
		/// <param name="solutionPath">Current solution path.</param>
		/// <returns>Lookup of canonical identifiers to display names.</returns>
		private static Dictionary<string, string> BuildNonBuildableItemNameIndex(string solutionPath)
		{
			var index = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

			if (string.IsNullOrWhiteSpace(solutionPath) || !File.Exists(solutionPath))
			{
				return index;
			}

			if (string.Equals(Path.GetExtension(solutionPath), ".slnx", StringComparison.OrdinalIgnoreCase))
			{
				BuildSlnxNonBuildableItemNameIndex(solutionPath, index);

				return index;
			}

			BuildSlnNonBuildableItemNameIndex(solutionPath, index);

			return index;
		}

		/// <summary>
		/// Loads non-buildable item names from an SLNX file.
		/// </summary>
		/// <param name="solutionPath">Current solution path.</param>
		/// <param name="index">Destination index.</param>
		private static void BuildSlnxNonBuildableItemNameIndex(string solutionPath, Dictionary<string, string> index)
		{
			try
			{
				var document = XDocument.Load(solutionPath);
				var basePath = Path.GetDirectoryName(solutionPath) ?? string.Empty;
				var projectNodes = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "Project", StringComparison.OrdinalIgnoreCase));

				foreach (var projectNode in projectNodes)
				{
					var type = projectNode.Attribute("Type")?.Value ?? string.Empty;
					var path = projectNode.Attribute("Path")?.Value ?? string.Empty;

					if (!string.Equals(type, "Folder", StringComparison.OrdinalIgnoreCase) && IsBuildableProjectPath(path))
					{
						continue;
					}

					var name = projectNode.Attribute("Name")?.Value;

					if (string.IsNullOrWhiteSpace(name))
					{
						name = Path.GetFileNameWithoutExtension(path);
					}

					if (string.IsNullOrWhiteSpace(name))
					{
						continue;
					}

					AddIndexEntry(index, path, name!, basePath);
					AddIndexEntry(index, projectNode.Attribute("Guid")?.Value, name!, basePath);
					AddIndexEntry(index, projectNode.Attribute("Id")?.Value, name!, basePath);
					AddIndexEntry(index, projectNode.Attribute("ProjectGuid")?.Value, name!, basePath);
				}
			}
			catch (Exception ex)
			{
				// Fail safe: if SLNX parsing fails, keep an empty index so the review window can still load.
				Trace.WriteLine($"[MSBuildGuard] Failed to parse SLNX non-buildable item names from '{solutionPath}'. {ex}");
			}
		}

		/// <summary>
		/// Loads non-buildable item names from an SLN file.
		/// </summary>
		/// <param name="solutionPath">Current solution path.</param>
		/// <param name="index">Destination index.</param>
		private static void BuildSlnNonBuildableItemNameIndex(string solutionPath, Dictionary<string, string> index)
		{
			try
			{
				var basePath = Path.GetDirectoryName(solutionPath) ?? string.Empty;

				foreach (var line in File.ReadLines(solutionPath))
				{
					if (!line.StartsWith("Project(", StringComparison.OrdinalIgnoreCase))
					{
						continue;
					}

					if (!TryParseSlnProjectDefinitionLine(line, out var name, out var relativePath, out var projectGuid))
					{
						continue;
					}

					if (IsBuildableProjectPath(relativePath) || string.IsNullOrWhiteSpace(name))
					{
						continue;
					}

					AddIndexEntry(index, relativePath, name, basePath);
					AddIndexEntry(index, projectGuid, name, basePath);
				}
			}
			catch (Exception ex)
			{
				// Fail safe: if SLN parsing fails, keep an empty index so the review window can still load.
				Trace.WriteLine($"[MSBuildGuard] Failed to parse SLN non-buildable item names from '{solutionPath}'. {ex}");
			}
		}

		/// <summary>
		/// Tries to parse an SLN project definition line using quote-aware extraction.
		/// </summary>
		/// <param name="line">The raw SLN line.</param>
		/// <param name="name">Parsed project display name.</param>
		/// <param name="relativePath">Parsed project relative path.</param>
		/// <param name="projectGuid">Parsed project guid.</param>
		/// <returns><c>true</c> when the line is parsed successfully; otherwise <c>false</c>.</returns>
		private static bool TryParseSlnProjectDefinitionLine(string line, out string name, out string relativePath, out string projectGuid)
		{
			name = string.Empty;
			relativePath = string.Empty;
			projectGuid = string.Empty;

			if (string.IsNullOrWhiteSpace(line))
			{
				return false;
			}

			var quotedValues = new List<string>();
			var searchIndex = 0;

			while (searchIndex < line.Length)
			{
				var startQuote = line.IndexOf('"', searchIndex);

				if (startQuote < 0)
				{
					break;
				}

				var endQuote = line.IndexOf('"', startQuote + 1);

				if (endQuote < 0)
				{
					break;
				}

				quotedValues.Add(line.Substring(startQuote + 1, endQuote - startQuote - 1));
				searchIndex = endQuote + 1;
			}

			if (quotedValues.Count < 3)
			{
				return false;
			}

			name = quotedValues[quotedValues.Count - 3].Trim();
			relativePath = quotedValues[quotedValues.Count - 2].Trim();
			projectGuid = quotedValues[quotedValues.Count - 1].Trim();

			return !string.IsNullOrWhiteSpace(name) &&
				!string.IsNullOrWhiteSpace(relativePath) &&
				!string.IsNullOrWhiteSpace(projectGuid);
		}

		/// <summary>
		/// Resolves a display name for non-buildable solution items.
		/// </summary>
		/// <param name="index">Resolved non-buildable name index.</param>
		/// <param name="projectPath">Project path or hierarchy identifier.</param>
		/// <returns>The resolved display name.</returns>
		private static string ResolveNonBuildableItemDisplayName(Dictionary<string, string> index, string projectPath)
		{
			if (index.TryGetValue(projectPath, out var displayName))
			{
				return displayName;
			}

			var guidKey = NormalizeGuidKey(projectPath);

			if (!string.IsNullOrWhiteSpace(guidKey) && index.TryGetValue(guidKey, out displayName))
			{
				return displayName;
			}

			return Path.GetFileNameWithoutExtension(projectPath);
		}

		/// <summary>
		/// Adds a normalized key/value pair to the non-buildable item display-name index.
		/// </summary>
		/// <param name="index">Destination index.</param>
		/// <param name="rawKey">Raw path or identifier key.</param>
		/// <param name="name">Display name value.</param>
		/// <param name="basePath">Solution directory for relative path normalization.</param>
		private static void AddIndexEntry(Dictionary<string, string> index, string? rawKey, string name, string basePath)
		{
			if (string.IsNullOrWhiteSpace(rawKey) || string.IsNullOrWhiteSpace(name))
			{
				return;
			}

			var key = rawKey!.Trim();

			index[key] = name;

			var guidKey = NormalizeGuidKey(key);

			if (!string.IsNullOrWhiteSpace(guidKey))
			{
				index[guidKey] = name;
			}

			if (!Path.IsPathRooted(key) && !string.IsNullOrWhiteSpace(basePath))
			{
				var fullPath = Path.GetFullPath(Path.Combine(basePath, key));
				index[fullPath] = name;
			}
		}

		/// <summary>
		/// Normalizes GUID-like keys for dictionary lookup.
		/// </summary>
		/// <param name="value">Candidate GUID text.</param>
		/// <returns>Normalized GUID text or empty when not a GUID.</returns>
		private static string NormalizeGuidKey(string? value)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				return string.Empty;
			}

			var trimmed = value!.Trim().Trim('{', '}');

			if (!Guid.TryParse(trimmed, out var guid))
			{
				return string.Empty;
			}

			return guid.ToString("D").ToUpperInvariant();
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

			var assemblyName     = parts[0];
			var assemblyVersion  = parts[1];
			var currentProjectPath = this.selectedProject != null && !string.Equals(this.selectedProject.Path, AllProjectsPath, StringComparison.OrdinalIgnoreCase)
				? this.selectedProject.Path
				: string.Empty;
			var assemblyPath     = AssemblySignatureService.ResolveAssemblyFilePath(finding.FilePath);

			if (!string.IsNullOrWhiteSpace(finding.PackageId) && !string.IsNullOrWhiteSpace(finding.PackageVersion))
			{
				var packageAssemblyPath = AssemblySignatureService.ResolveAssemblyFilePathFromPackageId(finding.PackageId, finding.PackageVersion);

				if (!string.IsNullOrWhiteSpace(packageAssemblyPath))
				{
					assemblyPath = packageAssemblyPath;
				}
			}

			var dialog = new TrustAssemblyDialog
			{
				Owner                 = Application.Current.MainWindow,
				WindowStartupLocation = System.Windows.WindowStartupLocation.CenterOwner,
				AssemblyName          = assemblyName,
				AssemblyVersion       = assemblyVersion,
				AssemblyPath          = assemblyPath,
				SolutionPath          = this.CurrentTargetPath,
				ProjectPath           = currentProjectPath
			};

			var result = dialog.ShowDialog();

			if (result != true)
			{
				return;
			}

			var trustStoreService = new TrustStoreService();
			var trustStorePath    = ResolveTrustStorePath(trustStoreService, dialog.SelectedScope, this.CurrentTargetPath, dialog.SelectedProjectPath);
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
				dialog.AssemblySubject,
				dialog.ExpiresAtUtc);

			if (MSBuildGuardPackage.Instance is MSBuildGuardPackage package)
			{
				await package.RescanSolutionSecurityReviewAsync();
			}
		}

		/// <summary>
		/// Resolves trust store path by selected UI scope.
		/// </summary>
		/// <param name="trustStoreService">Trust store service instance.</param>
		/// <param name="scope">Selected trust scope.</param>
		/// <param name="solutionPath">Current solution path.</param>
		/// <param name="projectPath">Current project path.</param>
		/// <returns>Resolved trust store path.</returns>
		private static string ResolveTrustStorePath(TrustStoreService trustStoreService, TrustScope scope, string solutionPath, string projectPath)
		{
			if (scope == TrustScope.Project && !string.IsNullOrWhiteSpace(projectPath))
			{
				return trustStoreService.GetProjectTrustPath(projectPath);
			}

			if (scope == TrustScope.Solution && !string.IsNullOrWhiteSpace(solutionPath))
			{
				return trustStoreService.GetSolutionTrustPath(solutionPath);
			}

			return trustStoreService.GetDefaultUserTrustPath();
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

		private const string SecurityReviewSettingsCollection = @"MSBuildGuard\SecurityReview\OnlyUntrustedIssues";

		private bool ReadOnlyUntrustedSetting(string scopePath)
		{
			ThreadHelper.ThrowIfNotOnUIThread();
			try
			{
				if (MSBuildGuardPackage.Instance is not MSBuildGuardPackage package)
				{
					return false;
				}

				var settingsManager = new ShellSettingsManager(package);
				var store = settingsManager.GetReadOnlySettingsStore(SettingsScope.UserSettings);

				if (!store.CollectionExists(SecurityReviewSettingsCollection))
				{
					return false;
				}

				// 1. Check Project scope if it is distinct from All and Solution
				var isAll = string.Equals(scopePath, AllProjectsPath, StringComparison.OrdinalIgnoreCase);
				var isSolution = !string.IsNullOrWhiteSpace(this.CurrentTargetPath) && string.Equals(scopePath, this.CurrentTargetPath, StringComparison.OrdinalIgnoreCase);

				if (!isAll && !isSolution)
				{
					var projectProperty = GetRegistryPropertyName(scopePath);
					if (store.PropertyExists(SecurityReviewSettingsCollection, projectProperty))
					{
						return store.GetBoolean(SecurityReviewSettingsCollection, projectProperty, false);
					}
				}

				// 2. Fall back to Solution scope if it is not the All scope and we have a Solution path
				if (!isAll && !string.IsNullOrWhiteSpace(this.CurrentTargetPath))
				{
					var solutionProperty = GetRegistryPropertyName(this.CurrentTargetPath);
					if (store.PropertyExists(SecurityReviewSettingsCollection, solutionProperty))
					{
						return store.GetBoolean(SecurityReviewSettingsCollection, solutionProperty, false);
					}
				}

				// 3. Fall back to All scope
				var allProperty = GetRegistryPropertyName(AllProjectsPath);
				if (store.PropertyExists(SecurityReviewSettingsCollection, allProperty))
				{
					return store.GetBoolean(SecurityReviewSettingsCollection, allProperty, false);
				}
			}
			catch (Exception ex)
			{
				Trace.WriteLine($"[MSBuildGuard] Failed to read OnlyUntrustedIssues setting for scope '{scopePath}': {ex}");
			}

			return false;
		}

		private static void SaveOnlyUntrustedSetting(string scopePath, bool value)
		{
			ThreadHelper.ThrowIfNotOnUIThread();
			try
			{
				if (MSBuildGuardPackage.Instance is not MSBuildGuardPackage package)
				{
					return;
				}

				var settingsManager = new ShellSettingsManager(package);
				var store = settingsManager.GetWritableSettingsStore(SettingsScope.UserSettings);

				if (!store.CollectionExists(SecurityReviewSettingsCollection))
				{
					store.CreateCollection(SecurityReviewSettingsCollection);
				}

				var propertyName = GetRegistryPropertyName(scopePath);
				store.SetBoolean(SecurityReviewSettingsCollection, propertyName, value);
			}
			catch (Exception ex)
			{
				Trace.WriteLine($"[MSBuildGuard] Failed to save OnlyUntrustedIssues setting for scope '{scopePath}': {ex}");
			}
		}

		private static string GetRegistryPropertyName(string scopePath)
		{
			if (string.IsNullOrWhiteSpace(scopePath))
			{
				return AllProjectsPath.ToLowerInvariant();
			}
			return scopePath.Replace('\\', '/').ToLowerInvariant();
		}
	}
}
