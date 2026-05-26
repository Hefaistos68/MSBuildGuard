using System;
using System.Collections.Generic;

namespace MSBuildGuard.Core
{
    /// <summary>
    /// Represents the type of target requested for scanning.
    /// </summary>
    public enum TargetKind
    {
        File,
        Folder,
        Solution,
        Repository
    }

    /// <summary>
    /// Represents the caller that requested a scan.
    /// </summary>
    public enum ScanRequestedBy
    {
        Cli,
        VisualStudio,
        GitHook,
        Explorer
    }

    /// <summary>
    /// Represents the requested scan depth.
    /// </summary>
    public enum ScanMode
    {
        Fast,
        Normal,
        Deep
    }

    /// <summary>
    /// Represents how a file was discovered during scanning.
    /// </summary>
    public enum FileDiscoverySource
    {
        Root,
        SolutionEntry,
        Import,
        ImplicitSdk,
        NuGetPackageAsset,
        WildcardImport,
        CommandArgument,
        Unknown
    }

    /// <summary>
    /// Represents the provenance kind for a package-provided asset.
    /// </summary>
    public enum PackageAssetKind
    {
        Unknown,
        Build,
        BuildTransitive,
        BuildMultiTargeting,
        Analyzer,
        Tool,
        Sdk
    }

    /// <summary>
    /// Represents package source evidence strength for package-origin metadata.
    /// </summary>
    public enum PackageSourceEvidenceKind
    {
        Unknown,
        RestoredMetadata,
        LockFileCorrelation,
        ConfigMapping,
        SingleConfiguredSource
    }

    /// <summary>
    /// Represents overall analysis completeness for a scanned file or report.
    /// </summary>
    public enum AnalysisStatus
    {
        Complete,
        Partial,
        Failed
    }

    /// <summary>
    /// Represents how an import path was resolved during scanning.
    /// </summary>
    public enum ImportResolutionKind
    {
        Unresolved,
        Relative,
        Absolute,
        Wildcard,
        Remote,
        EnvironmentExpanded
    }

    /// <summary>
    /// Represents the file kind of an MSBuild-related file.
    /// </summary>
    public enum MsBuildFileKind
    {
        Project,
        Props,
        Targets,
        Solution,
        UnknownMsBuildXml
    }

    /// <summary>
    /// Represents severity for a finding.
    /// </summary>
    public enum FindingSeverity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4,
        None = -1
    }

    /// <summary>
    /// Represents confidence for a finding.
    /// </summary>
    public enum FindingConfidence
    {
        Low,
        Medium,
        High
    }

    /// <summary>
    /// Represents default policy action for a finding.
    /// </summary>
    public enum PolicyAction
    {
        Allow,
        Warn,
        RequireApproval,
        Block
    }

    /// <summary>
    /// Represents the recommended action for the overall scan report.
    /// </summary>
    public enum RecommendedAction
    {
        Allow,
        Warn,
        RequireApproval,
        Block
    }

    /// <summary>
    /// Represents trust-context metadata used while scanning.
    /// </summary>
    public sealed class ScanTrustContext
    {
        /// <summary>
        /// Gets or sets a value indicating whether repository state is trusted.
        /// </summary>
        public bool IsRepositoryTrusted { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether Mark-of-the-Web state is considered trusted.
        /// </summary>
        public bool IsMarkOfTheWebTrusted { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether baseline state is trusted.
        /// </summary>
        public bool IsBaselineTrusted { get; set; }

        /// <summary>
        /// Gets or sets the active policy profile identifier.
        /// </summary>
        public string PolicyProfile { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the repository remote associated with the scan context.
        /// </summary>
        public string RepositoryRemote { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the repository branch associated with the scan context.
        /// </summary>
        public string Branch { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the repository commit SHA associated with the scan context.
        /// </summary>
        public string CommitSha { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents one resolved import path observed during scanning.
    /// </summary>
    public sealed class ResolvedImportRecord
    {
        /// <summary>
        /// Gets or sets the original import expression.
        /// </summary>
        public string OriginalPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the resolved file path when available.
        /// </summary>
        public string ResolvedPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the resolution kind.
        /// </summary>
        public ImportResolutionKind ResolutionKind { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the import resolved successfully.
        /// </summary>
        public bool IsResolved { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the resolved import path is risky.
        /// </summary>
        public bool IsRisky { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the import is consumed by multiple projects.
        /// </summary>
        public bool IsImportedByMultipleProjects { get; set; }

        /// <summary>
        /// Gets or sets the package identifier associated with the resolved import.
        /// </summary>
        public string PackageId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package version associated with the resolved import.
        /// </summary>
        public string PackageVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package source label associated with the resolved import.
        /// </summary>
        public string PackageSource { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package source evidence kind associated with the resolved import.
        /// </summary>
        public PackageSourceEvidenceKind PackageSourceEvidenceKind { get; set; } = PackageSourceEvidenceKind.Unknown;

        /// <summary>
        /// Gets or sets the package source evidence path associated with the resolved import.
        /// </summary>
        public string PackageSourceEvidencePath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package content hash associated with the resolved import when known.
        /// </summary>
        public string PackageContentHash { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether package source attribution for the resolved import is inferred.
        /// </summary>
        public bool IsPackageSourceInferred { get; set; }

        /// <summary>
        /// Gets or sets the package asset kind associated with the resolved import.
        /// </summary>
        public PackageAssetKind PackageAssetKind { get; set; } = PackageAssetKind.Unknown;

        /// <summary>
        /// Gets or sets a value indicating whether the resolved import originated from a transitive package.
        /// </summary>
        public bool IsTransitivePackage { get; set; }

        /// <summary>
        /// Gets or sets the project path or package edge that introduced the package asset.
        /// </summary>
        public string IntroducedViaProject { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package asset path inside the NuGet package cache or repository packages folder.
        /// </summary>
        public string NuGetAssetPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package signature state when known.
        /// </summary>
        public string PackageSignatureState { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SDK identifier associated with the import when it is an implicit SDK import.
        /// </summary>
        public string SdkIdentifier { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SDK version associated with the import when known.
        /// </summary>
        public string SdkVersion { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents baseline-comparison metadata for a scan report.
    /// </summary>
    public sealed class BaselineComparisonSummary
    {
        /// <summary>
        /// Gets or sets a value indicating whether a baseline was provided.
        /// </summary>
        public bool HasBaseline { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether drift was detected.
        /// </summary>
        public bool DriftDetected { get; set; }

        /// <summary>
        /// Gets or sets a human-readable comparison summary.
        /// </summary>
        public string Summary { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents a scan request target.
    /// </summary>
    public sealed class ScanTarget
    {
        /// <summary>
        /// Gets or sets the originally requested target path.
        /// </summary>
        public string TargetPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the target kind.
        /// </summary>
        public TargetKind TargetKind { get; set; }

        /// <summary>
        /// Gets or sets the root path used for scanning.
        /// </summary>
        public string RootPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the caller that requested this scan.
        /// </summary>
        public ScanRequestedBy RequestedBy { get; set; } = ScanRequestedBy.Cli;

        /// <summary>
        /// Gets or sets the requested scan mode.
        /// </summary>
        public ScanMode ScanMode { get; set; } = ScanMode.Normal;

        /// <summary>
        /// Gets or sets trust-context metadata.
        /// </summary>
        public ScanTrustContext TrustContext { get; set; } = new ScanTrustContext();
    }

    /// <summary>
    /// Represents one parse diagnostic for an MSBuild file.
    /// </summary>
    public sealed class ParseDiagnostic
    {
        /// <summary>
        /// Gets or sets the diagnostic message.
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the line number.
        /// </summary>
        public int Line { get; set; }

        /// <summary>
        /// Gets or sets the column number.
        /// </summary>
        public int Column { get; set; }
    }

    /// <summary>
    /// Represents one scanned MSBuild-related file.
    /// </summary>
    public sealed class MsBuildFileRecord
    {
        /// <summary>
        /// Gets or sets the full file path.
        /// </summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the file kind.
        /// </summary>
        public MsBuildFileKind FileKind { get; set; }

        /// <summary>
        /// Gets or sets the SHA256 hash of the original file content.
        /// </summary>
        public string Sha256 { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SHA256 hash of normalized file content.
        /// </summary>
        public string NormalizedSha256 { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether Mark-of-the-Web metadata exists.
        /// </summary>
        public bool HasMarkOfTheWeb { get; set; }

        /// <summary>
        /// Gets or sets how the file was discovered.
        /// </summary>
        public FileDiscoverySource DiscoveredFrom { get; set; } = FileDiscoverySource.Unknown;

        /// <summary>
        /// Gets import paths discovered from the file.
        /// </summary>
        public IList<string> Imports { get; } = new List<string>();

        /// <summary>
        /// Gets parse diagnostics collected while parsing.
        /// </summary>
        public IList<ParseDiagnostic> ParseDiagnostics { get; } = new List<ParseDiagnostic>();

        /// <summary>
        /// Gets resolved import metadata collected for the file.
        /// </summary>
        public IList<ResolvedImportRecord> ResolvedImports { get; } = new List<ResolvedImportRecord>();

        /// <summary>
        /// Gets or sets the number of files that import this file.
        /// </summary>
        public int ImportedByCount { get; set; }

        /// <summary>
        /// Gets or sets analysis completeness for the file.
        /// </summary>
        public AnalysisStatus AnalysisStatus { get; set; } = AnalysisStatus.Complete;

        /// <summary>
        /// Gets or sets analysis summary text for the file.
        /// </summary>
        public string AnalysisSummary { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package identifier associated with the file when it originates from a package asset.
        /// </summary>
        public string PackageId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package version associated with the file when it originates from a package asset.
        /// </summary>
        public string PackageVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package source label associated with the file when determinable.
        /// </summary>
        public string PackageSource { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package source evidence kind associated with the file.
        /// </summary>
        public PackageSourceEvidenceKind PackageSourceEvidenceKind { get; set; } = PackageSourceEvidenceKind.Unknown;

        /// <summary>
        /// Gets or sets the package source evidence path associated with the file.
        /// </summary>
        public string PackageSourceEvidencePath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package content hash associated with the file when known.
        /// </summary>
        public string PackageContentHash { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether package source attribution for the file is inferred.
        /// </summary>
        public bool IsPackageSourceInferred { get; set; }

        /// <summary>
        /// Gets or sets the package asset kind associated with the file.
        /// </summary>
        public PackageAssetKind PackageAssetKind { get; set; } = PackageAssetKind.Unknown;

        /// <summary>
        /// Gets or sets a value indicating whether the file originates from a transitive package asset.
        /// </summary>
        public bool IsTransitivePackage { get; set; }

        /// <summary>
        /// Gets or sets the project path or package edge that introduced the package asset.
        /// </summary>
        public string IntroducedViaProject { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the path of the package asset inside the restore location.
        /// </summary>
        public string NuGetAssetPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package signature state when known.
        /// </summary>
        public string PackageSignatureState { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SDK identifier declared or associated with the file.
        /// </summary>
        public string SdkIdentifier { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SDK version declared or associated with the file.
        /// </summary>
        public string SdkVersion { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents one security-relevant finding.
    /// </summary>
    public sealed class Finding
    {
        /// <summary>
        /// Gets or sets the rule identifier.
        /// </summary>
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the finding title.
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the finding description.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the severity.
        /// </summary>
        public FindingSeverity Severity { get; set; }

        /// <summary>
        /// Gets or sets the confidence.
        /// </summary>
        public FindingConfidence Confidence { get; set; }

        /// <summary>
        /// Gets or sets the file path associated with the finding.
        /// </summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets start line.
        /// </summary>
        public int StartLine { get; set; }

        /// <summary>
        /// Gets or sets start column.
        /// </summary>
        public int StartColumn { get; set; }

        /// <summary>
        /// Gets or sets end line.
        /// </summary>
        public int EndLine { get; set; }

        /// <summary>
        /// Gets or sets end column.
        /// </summary>
        public int EndColumn { get; set; }

        /// <summary>
        /// Gets or sets finding evidence.
        /// </summary>
        public string Evidence { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets recommendation text.
        /// </summary>
        public string Recommendation { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the effective policy action after evaluation.
        /// </summary>
        public PolicyAction PolicyAction { get; set; }

        /// <summary>
        /// Gets or sets the scanner-provided default action before policy evaluation.
        /// </summary>
        public PolicyAction ScannerPolicyAction { get; set; }

        /// <summary>
        /// Gets or sets the policy-evaluated action prior to trust/risk aggregation.
        /// </summary>
        public PolicyAction PolicyEvaluatedAction { get; set; }

        /// <summary>
        /// Gets or sets an optional explanation for policy action changes.
        /// </summary>
        public string PolicyActionReason { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets stable fingerprint for baseline suppression and approval.
        /// </summary>
        public string Fingerprint { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether the finding is new compared with baseline.
        /// </summary>
        public bool IsNewComparedWithBaseline { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the finding originates from a file imported by multiple projects.
        /// </summary>
        public bool IsInFileImportedByMultipleProjects { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the finding file has Mark-of-the-Web metadata.
        /// </summary>
        public bool FileHasMarkOfTheWeb { get; set; }

        /// <summary>
        /// Gets or sets the package identifier associated with the finding when it originates from a package asset.
        /// </summary>
        public string PackageId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package version associated with the finding when it originates from a package asset.
        /// </summary>
        public string PackageVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package source label associated with the finding when determinable.
        /// </summary>
        public string PackageSource { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package source evidence kind associated with the finding.
        /// </summary>
        public PackageSourceEvidenceKind PackageSourceEvidenceKind { get; set; } = PackageSourceEvidenceKind.Unknown;

        /// <summary>
        /// Gets or sets the package source evidence path associated with the finding.
        /// </summary>
        public string PackageSourceEvidencePath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package content hash associated with the finding when known.
        /// </summary>
        public string PackageContentHash { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether package source attribution for the finding is inferred.
        /// </summary>
        public bool IsPackageSourceInferred { get; set; }

        /// <summary>
        /// Gets or sets the package asset kind associated with the finding.
        /// </summary>
        public PackageAssetKind PackageAssetKind { get; set; } = PackageAssetKind.Unknown;

        /// <summary>
        /// Gets or sets a value indicating whether the finding originates from a transitive package asset.
        /// </summary>
        public bool IsTransitivePackage { get; set; }

        /// <summary>
        /// Gets or sets the project path or package edge that introduced the package asset.
        /// </summary>
        public string IntroducedViaProject { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the path of the package asset inside the restore location.
        /// </summary>
        public string NuGetAssetPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the package signature state when known.
        /// </summary>
        public string PackageSignatureState { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SDK identifier associated with the finding when it originates from an implicit SDK import.
        /// </summary>
        public string SdkIdentifier { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the SDK version associated with the finding when known.
        /// </summary>
        public string SdkVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether the finding is a new file detected during baseline comparison.
        /// Distinguishes baseline-drift detections (true) from static file-type detections (false).
        /// </summary>
        public bool IsNewInBaseline { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the finding is trusted.
        /// </summary>
        public bool IsTrusted { get; set; }
    }

    /// <summary>
    /// Represents a complete scan report.
    /// </summary>
    public sealed class ScanReport
    {
        /// <summary>
        /// Gets or sets report version.
        /// </summary>
        public string ReportVersion { get; set; } = "1.0";

        /// <summary>
        /// Gets or sets scanner version.
        /// </summary>
        public string ScannerVersion { get; set; } = "1.0.0";

        /// <summary>
        /// Gets or sets scan target metadata.
        /// </summary>
        public ScanTarget Target { get; set; } = new ScanTarget();

        /// <summary>
        /// Gets or sets scan start timestamp.
        /// </summary>
        public DateTimeOffset StartedAtUtc { get; set; }

        /// <summary>
        /// Gets or sets scan end timestamp.
        /// </summary>
        public DateTimeOffset CompletedAtUtc { get; set; }

        /// <summary>
        /// Gets scanned files.
        /// </summary>
        public IList<MsBuildFileRecord> FilesScanned { get; } = new List<MsBuildFileRecord>();

        /// <summary>
        /// Gets skipped files.
        /// </summary>
        public IList<string> FilesSkipped { get; } = new List<string>();

        /// <summary>
        /// Gets findings.
        /// </summary>
        public IList<Finding> Findings { get; } = new List<Finding>();

        /// <summary>
        /// Gets or sets aggregate risk score.
        /// </summary>
        public int RiskScore { get; set; }

        /// <summary>
        /// Gets or sets the report-level recommended action.
        /// </summary>
        public RecommendedAction RecommendedAction { get; set; }

        /// <summary>
        /// Gets or sets baseline comparison summary.
        /// </summary>
        public BaselineComparisonSummary BaselineComparison { get; set; } = new BaselineComparisonSummary();

        /// <summary>
        /// Gets or sets active policy profile.
        /// </summary>
        public string PolicyProfile { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets overall analysis completeness for the report.
        /// </summary>
        public AnalysisStatus AnalysisStatus { get; set; } = AnalysisStatus.Complete;

        /// <summary>
        /// Gets or sets overall analysis summary text.
        /// </summary>
        public string AnalysisSummary { get; set; } = string.Empty;
    }
}
