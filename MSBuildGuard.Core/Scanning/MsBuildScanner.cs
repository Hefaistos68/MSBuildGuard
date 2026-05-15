using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace MSBuildGuard.Core.Scanning
{
    /// <summary>
    /// Scans MSBuild-related files and produces a security report.
    /// </summary>
    public sealed class MsBuildScanner
    {
        /// <summary>
        /// Gets supported MSBuild-related file extensions used during discovery.
        /// </summary>
        private static readonly string[] MsBuildExtensions =
        {
            ".csproj",
            ".vbproj",
            ".fsproj",
            ".proj",
            ".props",
            ".targets",
            ".sln",
            ".slnx"
        };

        private static readonly string[] WellKnownMsBuildFileNames =
        {
            "Directory.Build.props",
            "Directory.Build.targets"
        };

        private static readonly string[] ProcessCreationIndicators =
        {
            "System.Diagnostics.Process",
            "Process.Start(",
            "CreateProcess(",
            "cmd.exe",
            "powershell",
            "pwsh"
        };

        private static readonly string[] ReflectionInteropIndicators =
        {
            "System.Reflection",
            "Assembly.Load",
            "Activator.CreateInstance",
            "GetType(",
            "dynamic ",
            "DllImport",
            "Marshal.GetDelegateForFunctionPointer",
            "LoadLibrary"
        };

        private static readonly string[] DefaultAdditionalBlockedAssemblies = Array.Empty<string>();

        private static readonly Regex Base64LikeRegex = new Regex("[A-Za-z0-9+/]{200,}={0,2}", RegexOptions.Compiled);

        private static readonly CSharpParseOptions RoslynParseOptions = new CSharpParseOptions(LanguageVersion.Latest);

        /// <summary>
        /// Represents one queued discovery candidate.
        /// </summary>
        private sealed class DiscoveryCandidate
        {
            /// <summary>
            /// Gets or sets the candidate path.
            /// </summary>
            public string Path { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets the discovery source.
            /// </summary>
            public FileDiscoverySource Source { get; set; }
        }

        /// <summary>
        /// Represents Roslyn-backed inline code analysis results.
        /// </summary>
        private sealed class InlineCodeAnalysisResult
        {
            /// <summary>
            /// Gets or sets a value indicating whether process creation APIs were detected.
            /// </summary>
            public bool UsesProcessCreationApis { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether reflection or interop APIs were detected.
            /// </summary>
            public bool UsesReflectionOrInterop { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether encoded payload indicators were detected.
            /// </summary>
            public bool ContainsEncodedPayloadIndicators { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether parsing completed successfully.
            /// </summary>
            public bool ParsedSuccessfully { get; set; }
        }

        /// <summary>
        /// Represents cached XML parse results for a scanned file.
        /// </summary>
        private sealed class ParsedDocumentCacheEntry
        {
            /// <summary>
            /// Gets or sets the parsed XML document.
            /// </summary>
            public XDocument? Document { get; set; }

            /// <summary>
            /// Gets or sets the parse exception when parsing failed.
            /// </summary>
            public XmlException? ParseException { get; set; }
        }

        /// <summary>
        /// Provides file-system operations used by the scanner.
        /// </summary>
        private readonly IFileSystem _fileSystem;

        /// <summary>
        /// Caches file content for the current scan.
        /// </summary>
        private readonly Dictionary<string, string> _fileContentCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Caches parsed XML documents for the current scan.
        /// </summary>
        private readonly Dictionary<string, ParsedDocumentCacheEntry> _parsedDocumentCache = new Dictionary<string, ParsedDocumentCacheEntry>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Caches inline-code analysis results for the current scan.
        /// </summary>
        private readonly Dictionary<string, InlineCodeAnalysisResult> _inlineCodeAnalysisCache = new Dictionary<string, InlineCodeAnalysisResult>(StringComparer.Ordinal);

        /// <summary>
        /// Caches package asset provenance by resolved package asset path for the current scan.
        /// </summary>
        private readonly Dictionary<string, PackageAssetProvenanceRecord> _packageAssetProvenanceCache = new Dictionary<string, PackageAssetProvenanceRecord>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Tracks restored assets files already processed during the current scan.
        /// </summary>
        private readonly HashSet<string> _processedAssetsFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Parses restored NuGet assets metadata.
        /// </summary>
        private readonly PackageAssetsFileParser _packageAssetsFileParser = new PackageAssetsFileParser();

        /// <summary>
        /// Resolves evidence-based NuGet package provenance.
        /// </summary>
        private readonly PackageProvenanceResolver _packageProvenanceResolver;

        /// <summary>
        /// Emits scanner activity messages for host-level diagnostics.
        /// </summary>
        private readonly Action<string>? _activityLogger;

        /// <summary>
        /// Stores normalized file extensions used during discovery.
        /// </summary>
        private readonly string[] _msBuildExtensions;

        /// <summary>
        /// Stores normalized process creation indicator tokens.
        /// </summary>
        private readonly string[] _processCreationIndicators;

        /// <summary>
        /// Stores normalized reflection or interop indicator tokens.
        /// </summary>
        private readonly string[] _reflectionInteropIndicators;

        /// <summary>
        /// Stores normalized assembly names that are blocked when referenced.
        /// </summary>
        private readonly string[] _additionalBlockedAssemblies;

        /// <summary>
        /// Initializes a new instance of the <see cref="MsBuildScanner"/> class.
        /// </summary>
        /// <param name="fileSystem">The file system abstraction used by the scanner.</param>
        /// <param name="activityLogger">Optional activity logger callback.</param>
        public MsBuildScanner(IFileSystem? fileSystem = null, Action<string>? activityLogger = null)
            : this(fileSystem, activityLogger, null, null, null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MsBuildScanner"/> class with caller-provided rule settings.
        /// </summary>
        /// <param name="fileSystem">The file system abstraction used by the scanner.</param>
        /// <param name="activityLogger">Optional activity logger callback.</param>
        /// <param name="msBuildExtensions">Optional MSBuild-related file extensions to discover.</param>
        /// <param name="processCreationIndicators">Optional process creation indicators.</param>
        /// <param name="reflectionInteropIndicators">Optional reflection and interop indicators.</param>
        /// <param name="additionalBlockedAssemblies">Optional additional assemblies to flag when referenced.</param>
        public MsBuildScanner(
            IFileSystem? fileSystem,
            Action<string>? activityLogger,
            IEnumerable<string>? msBuildExtensions,
            IEnumerable<string>? processCreationIndicators,
            IEnumerable<string>? reflectionInteropIndicators,
            IEnumerable<string>? additionalBlockedAssemblies)
        {
            _fileSystem = fileSystem ?? new DefaultFileSystem();
            _packageProvenanceResolver = new PackageProvenanceResolver(_fileSystem);
            _activityLogger = activityLogger;
            _msBuildExtensions = NormalizeExtensions(msBuildExtensions, MsBuildExtensions);
            _processCreationIndicators = NormalizeValues(processCreationIndicators, ProcessCreationIndicators);
            _reflectionInteropIndicators = NormalizeValues(reflectionInteropIndicators, ReflectionInteropIndicators);
            _additionalBlockedAssemblies = NormalizeValues(additionalBlockedAssemblies, DefaultAdditionalBlockedAssemblies);
        }

        /// <summary>
        /// Scans the provided path for MSBuild risk indicators and returns a report.
        /// </summary>
        /// <param name="path">The file, folder, or solution path to scan.</param>
        /// <returns>A populated <see cref="ScanReport"/>.</returns>
        public ScanReport Scan(string path)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            var startedAtUtc = DateTimeOffset.UtcNow;
            var fullPath = Path.GetFullPath(path);
            var target = CreateTarget(fullPath);

            ResetCaches();

            var report = new ScanReport
            {
                StartedAtUtc  = startedAtUtc,
                Target        = target,
                PolicyProfile = target.TrustContext.PolicyProfile
            };

            var records = DiscoverFileRecords(target, report.FilesSkipped);

            foreach (var record in records)
            {
                report.FilesScanned.Add(record);

                var findings = EvaluateRules(record);

                foreach (var finding in findings)
                {
                    report.Findings.Add(finding);
                }
            }

            ApplyAnalysisStatus(report);

            if (report.Findings.Count == 0)
            {
                report.Findings.Add(CreateNoIssuesFinding(report.Target.TargetPath));
            }

            report.RiskScore = report.Findings.Sum(SeverityScore);
            report.RecommendedAction = MapAction(report.RiskScore);
            report.CompletedAtUtc = DateTimeOffset.UtcNow;

            return report;
        }

        /// <summary>
        /// Creates the synthetic no-issues finding used when a scan reports no issues.
        /// </summary>
        /// <param name="targetPath">The scanned target path.</param>
        /// <returns>The synthetic finding.</returns>
        private static Finding CreateNoIssuesFinding(string targetPath)
        {
            return new Finding
            {
                Id = "MBG000",
                Title = "No issues detected",
                Description = "No issues detected.",
                Severity = FindingSeverity.None,
                Confidence = FindingConfidence.High,
                FilePath = targetPath ?? string.Empty,
                StartLine = 1,
                StartColumn = 1,
                EndLine = 1,
                EndColumn = 1,
                Evidence = "Scan completed with no issues.",
                Recommendation = "No action required.",
                PolicyAction = PolicyAction.Allow,
                ScannerPolicyAction = PolicyAction.Allow,
                PolicyEvaluatedAction = PolicyAction.Allow,
                Fingerprint = string.Concat("MBG000|", targetPath ?? string.Empty)
            };
        }

        /// <summary>
        /// Converts finding severity into a deterministic numeric score.
        /// </summary>
        /// <param name="finding">The finding to score.</param>
        /// <returns>The severity score value.</returns>
        private static int SeverityScore(Finding finding)
        {
            switch (finding.Severity)
            {
                case FindingSeverity.None:
                case FindingSeverity.Info:
                    return 0;
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
        /// Maps an aggregate risk score to a report-level recommended action.
        /// </summary>
        /// <param name="riskScore">The aggregate risk score.</param>
        /// <returns>The recommended action for the score band.</returns>
        private static RecommendedAction MapAction(int riskScore)
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
        /// Creates scan target metadata for the provided path.
        /// </summary>
        /// <param name="fullPath">The normalized absolute target path.</param>
        /// <returns>The scan target metadata.</returns>
        private static ScanTarget CreateTarget(string fullPath)
        {
            if (Directory.Exists(fullPath))
            {
                return new ScanTarget
                {
                    RequestedBy  = ScanRequestedBy.Cli,
                    RootPath     = fullPath,
                    ScanMode     = ScanMode.Normal,
                    TargetKind   = TargetKind.Folder,
                    TargetPath   = fullPath,
                    TrustContext = new ScanTrustContext
                    {
                        IsBaselineTrusted      = false,
                        IsMarkOfTheWebTrusted  = false,
                        IsRepositoryTrusted    = false,
                        PolicyProfile          = string.Empty
                    }
                };
            }

            var extension = Path.GetExtension(fullPath);

            if (string.Equals(extension, ".sln", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".slnx", StringComparison.OrdinalIgnoreCase))
            {
                return new ScanTarget
                {
                    RequestedBy  = ScanRequestedBy.Cli,
                    RootPath     = Path.GetDirectoryName(fullPath) ?? fullPath,
                    ScanMode     = ScanMode.Normal,
                    TargetKind   = TargetKind.Solution,
                    TargetPath   = fullPath,
                    TrustContext = new ScanTrustContext
                    {
                        IsBaselineTrusted      = false,
                        IsMarkOfTheWebTrusted  = false,
                        IsRepositoryTrusted    = false,
                        PolicyProfile          = string.Empty
                    }
                };
            }

            return new ScanTarget
            {
                RequestedBy  = ScanRequestedBy.Cli,
                RootPath     = Path.GetDirectoryName(fullPath) ?? fullPath,
                ScanMode     = ScanMode.Normal,
                TargetKind   = TargetKind.File,
                TargetPath   = fullPath,
                TrustContext = new ScanTrustContext
                {
                    IsBaselineTrusted      = false,
                    IsMarkOfTheWebTrusted  = false,
                    IsRepositoryTrusted    = false,
                    PolicyProfile          = string.Empty
                }
            };
        }

        /// <summary>
        /// Discovers candidate MSBuild files for a target and resolves imports transitively.
        /// </summary>
        /// <param name="target">The scan target metadata.</param>
        /// <param name="filesSkipped">The report collection used to track skipped files.</param>
        /// <returns>A sorted list of discovered file records.</returns>
        private List<MsBuildFileRecord> DiscoverFileRecords(ScanTarget target, IList<string> filesSkipped)
        {
            var records = new Dictionary<string, MsBuildFileRecord>(StringComparer.OrdinalIgnoreCase);
            var importers = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            var queued = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var queue = new Queue<DiscoveryCandidate>();

            foreach (var seed in GetInitialCandidates(target))
            {
                EnqueueCandidate(queue, queued, seed.Path, seed.Source);
            }

            while (queue.Count > 0)
            {
                var candidate = queue.Dequeue();

                if (records.ContainsKey(candidate.Path))
                {
                    continue;
                }

                if (!_fileSystem.FileExists(candidate.Path))
                {
                    if (!filesSkipped.Contains(candidate.Path, StringComparer.OrdinalIgnoreCase))
                    {
                        filesSkipped.Add(candidate.Path);
                    }

                    continue;
                }

                var record = BuildFileRecord(candidate.Path, candidate.Source);

                records[record.Path] = record;

                EnqueuePackageAssetCandidates(queue, queued, record);

                foreach (var resolvedImport in record.ResolvedImports)
                {
                    if (!resolvedImport.IsResolved || string.IsNullOrWhiteSpace(resolvedImport.ResolvedPath))
                    {
                        continue;
                    }

                    if (!importers.TryGetValue(resolvedImport.ResolvedPath, out var importerSet))
                    {
                        importerSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        importers[resolvedImport.ResolvedPath] = importerSet;
                    }

                    importerSet.Add(record.Path);

                    if (!IsSupportedMsBuildPath(resolvedImport.ResolvedPath))
                    {
                        continue;
                    }

                    var importSource = resolvedImport.ResolutionKind == ImportResolutionKind.Wildcard
                        ? FileDiscoverySource.WildcardImport
                        : FileDiscoverySource.Import;

                    EnqueueCandidate(queue, queued, resolvedImport.ResolvedPath, importSource);
                }
            }

            foreach (var entry in importers)
            {
                if (records.TryGetValue(entry.Key, out var importedRecord))
                {
                    importedRecord.ImportedByCount = entry.Value.Count;
                }
            }

            foreach (var record in records.Values)
            {
                foreach (var resolvedImport in record.ResolvedImports)
                {
                    if (!resolvedImport.IsResolved || string.IsNullOrWhiteSpace(resolvedImport.ResolvedPath))
                    {
                        continue;
                    }

                    if (importers.TryGetValue(resolvedImport.ResolvedPath, out var importerSet))
                    {
                        resolvedImport.IsImportedByMultipleProjects = importerSet.Count > 1;
                    }
                }
            }

            return records.Values.OrderBy(value => value.Path, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>
        /// Gets initial discovery candidates for the scan target.
        /// </summary>
        /// <param name="target">The scan target metadata.</param>
        /// <returns>The initial discovery candidates.</returns>
        private IEnumerable<DiscoveryCandidate> GetInitialCandidates(ScanTarget target)
        {
            if (target.TargetKind == TargetKind.File)
            {
                yield return new DiscoveryCandidate
                {
                    Path   = target.TargetPath,
                    Source = FileDiscoverySource.CommandArgument
                };

                yield break;
            }

            if (target.TargetKind == TargetKind.Solution)
            {
                yield return new DiscoveryCandidate
                {
                    Path   = target.TargetPath,
                    Source = FileDiscoverySource.CommandArgument
                };

                foreach (var solutionFile in ParseSolutionEntries(target.TargetPath))
                {
                    yield return new DiscoveryCandidate
                    {
                        Path   = solutionFile,
                        Source = FileDiscoverySource.SolutionEntry
                    };
                }

                yield break;
            }

            if (!_fileSystem.DirectoryExists(target.RootPath))
            {
                yield break;
            }

            foreach (var extension in _msBuildExtensions)
            {
                foreach (var discovered in _fileSystem.EnumerateFiles(target.RootPath, $"*{extension}"))
                {
                    yield return new DiscoveryCandidate
                    {
                        Path   = discovered,
                        Source = FileDiscoverySource.Root
                    };
                }
            }

            foreach (var fileName in WellKnownMsBuildFileNames)
            {
                var candidatePath = Path.Combine(target.RootPath, fileName);
                if (_fileSystem.FileExists(candidatePath))
                {
                    yield return new DiscoveryCandidate
                    {
                        Path   = candidatePath,
                        Source = FileDiscoverySource.Root
                    };
                }
            }
        }

        /// <summary>
        /// Enqueues a discovery candidate once per normalized path.
        /// </summary>
        /// <param name="queue">The discovery queue.</param>
        /// <param name="queued">The set of queued paths.</param>
        /// <param name="path">The candidate path.</param>
        /// <param name="source">The candidate discovery source.</param>
        private static void EnqueueCandidate(Queue<DiscoveryCandidate> queue, HashSet<string> queued, string path, FileDiscoverySource source)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            var fullPath = Path.GetFullPath(path);

            if (!queued.Add(fullPath))
            {
                return;
            }

            queue.Enqueue(new DiscoveryCandidate
            {
                Path   = fullPath,
                Source = source
            });
        }

        /// <summary>
        /// Parses project entries from a solution file.
        /// </summary>
        /// <param name="solutionPath">The solution file path.</param>
        /// <returns>A sequence of resolved project file paths.</returns>
        private IEnumerable<string> ParseSolutionEntries(string solutionPath)
        {
            if (!_fileSystem.FileExists(solutionPath))
            {
                return Enumerable.Empty<string>();
            }

            var content = _fileSystem.ReadAllText(solutionPath);
            var basePath = Path.GetDirectoryName(solutionPath) ?? string.Empty;
            var files = new List<string>();

            if (string.Equals(Path.GetExtension(solutionPath), ".slnx", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var document = XDocument.Parse(content);
                    var projectNodes = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "Project", StringComparison.OrdinalIgnoreCase));

                    foreach (var projectNode in projectNodes)
                    {
                        var projectPath = projectNode.Attribute("Path")?.Value;

                        if (string.IsNullOrWhiteSpace(projectPath))
                        {
                            continue;
                        }

                        if (Path.IsPathRooted(projectPath))
                        {
                            files.Add(Path.GetFullPath(projectPath));

                            continue;
                        }

                        files.Add(Path.GetFullPath(Path.Combine(basePath, projectPath)));
                    }

                    return files;
                }
                catch
                {
                    return files;
                }
            }

            var lines = content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

            foreach (var line in lines)
            {
                if (line.IndexOf(".csproj", StringComparison.OrdinalIgnoreCase) < 0 &&
                    line.IndexOf(".vbproj", StringComparison.OrdinalIgnoreCase) < 0 &&
                    line.IndexOf(".fsproj", StringComparison.OrdinalIgnoreCase) < 0 &&
                    line.IndexOf(".proj", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    continue;
                }

                var parts = line.Split(',');

                if (parts.Length < 2)
                {
                    continue;
                }

                var projectPath = parts[1].Trim().Trim('"');

                if (Path.IsPathRooted(projectPath))
                {
                    files.Add(projectPath);

                    continue;
                }

                files.Add(Path.GetFullPath(Path.Combine(basePath, projectPath)));
            }

            return files;
        }

        /// <summary>
        /// Builds a scanned file record including hashes, imports, and parse diagnostics.
        /// </summary>
        /// <param name="path">The file path to process.</param>
        /// <returns>The populated file record.</returns>
        private MsBuildFileRecord BuildFileRecord(string path, FileDiscoverySource discoveredFrom)
        {
            var content = GetFileContent(path);
            var normalized = NormalizeContent(content);
            var record = new MsBuildFileRecord
            {
                DiscoveredFrom   = discoveredFrom,
                FileKind         = Classify(path),
                HasMarkOfTheWeb  = _fileSystem.HasMarkOfTheWeb(path),
                NormalizedSha256 = Sha256(normalized),
                Path             = path,
                Sha256           = Sha256(content)
            };

            ApplyPackageAssetMetadata(record);

            if (!LooksLikeXml(path, content))
            {
                return record;
            }

            var parsedDocument = GetParsedDocument(path, content);

            if (parsedDocument.ParseException == null && parsedDocument.Document != null)
            {
                ApplySdkMetadata(parsedDocument.Document, record);
                ExtractImports(parsedDocument.Document, record);

                if (record.ResolvedImports.Any(importRecord => !importRecord.IsResolved))
                {
                    record.AnalysisStatus = AnalysisStatus.Partial;
                    record.AnalysisSummary = "One or more imports could not be fully resolved during static analysis.";
                }
            }
            else if (parsedDocument.ParseException != null)
            {
                record.ParseDiagnostics.Add(new ParseDiagnostic
                {
                    Column  = parsedDocument.ParseException.LinePosition,
                    Line    = parsedDocument.ParseException.LineNumber,
                    Message = parsedDocument.ParseException.Message
                });

                record.AnalysisStatus = AnalysisStatus.Failed;
                record.AnalysisSummary = "The file could not be parsed for complete analysis.";
            }

            return record;
        }

        /// <summary>
        /// Extracts import paths from an MSBuild XML document.
        /// </summary>
        /// <param name="document">The parsed XML document.</param>
        /// <param name="record">The destination file record.</param>
        private void ExtractImports(XDocument document, MsBuildFileRecord record)
        {
            var imports = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "Import", StringComparison.OrdinalIgnoreCase));
            var basePath = Path.GetDirectoryName(record.Path) ?? string.Empty;

            foreach (var import in imports)
            {
                var projectAttribute = import.Attribute("Project");

                if (projectAttribute == null)
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(projectAttribute.Value))
                {
                    continue;
                }

                record.Imports.Add(projectAttribute.Value);

                foreach (var resolvedImport in ResolveImports(projectAttribute.Value, basePath))
                {
                    ApplyResolvedImportMetadata(resolvedImport);
                    record.ResolvedImports.Add(resolvedImport);
                }
            }
        }

        /// <summary>
        /// Resolves one import path into zero or more import records.
        /// </summary>
        /// <param name="importPath">The raw import path expression.</param>
        /// <param name="basePath">The base path of the importing file.</param>
        /// <returns>The resolved import records.</returns>
        private IEnumerable<ResolvedImportRecord> ResolveImports(string importPath, string basePath)
        {
            var expandedPath = Environment.ExpandEnvironmentVariables(importPath);
            var resolutionKind = string.Equals(expandedPath, importPath, StringComparison.Ordinal)
                ? ImportResolutionKind.Relative
                : ImportResolutionKind.EnvironmentExpanded;

            if (expandedPath.IndexOf("$(", StringComparison.OrdinalIgnoreCase) >= 0 ||
                expandedPath.IndexOf("%(", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                yield return CreateResolvedImportRecord(importPath, expandedPath, ImportResolutionKind.Unresolved, false);

                yield break;
            }

            if (expandedPath.StartsWith("\\\\", StringComparison.OrdinalIgnoreCase) ||
                expandedPath.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                expandedPath.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                yield return CreateResolvedImportRecord(importPath, expandedPath, ImportResolutionKind.Remote, false);

                yield break;
            }

            if (expandedPath.IndexOf('*') >= 0 || expandedPath.IndexOf('?') >= 0)
            {
                foreach (var wildcardRecord in ResolveWildcardImports(importPath, expandedPath, basePath))
                {
                    yield return wildcardRecord;
                }

                yield break;
            }

            var resolvedPath = Path.IsPathRooted(expandedPath)
                ? Path.GetFullPath(expandedPath)
                : Path.GetFullPath(Path.Combine(basePath, expandedPath));

            yield return CreateResolvedImportRecord(importPath, resolvedPath, resolutionKind == ImportResolutionKind.EnvironmentExpanded ? ImportResolutionKind.EnvironmentExpanded : Path.IsPathRooted(expandedPath) ? ImportResolutionKind.Absolute : ImportResolutionKind.Relative, _fileSystem.FileExists(resolvedPath));
        }

        /// <summary>
        /// Resolves wildcard-based import paths.
        /// </summary>
        /// <param name="originalPath">The original import expression.</param>
        /// <param name="expandedPath">The environment-expanded import expression.</param>
        /// <param name="basePath">The base path of the importing file.</param>
        /// <returns>The resolved wildcard import records.</returns>
        private IEnumerable<ResolvedImportRecord> ResolveWildcardImports(string originalPath, string expandedPath, string basePath)
        {
            var resolvedDirectory = Path.GetDirectoryName(expandedPath);
            var searchPattern = Path.GetFileName(expandedPath);

            if (string.IsNullOrWhiteSpace(resolvedDirectory) && !Path.IsPathRooted(expandedPath))
            {
                resolvedDirectory = basePath;
            }

            if (!string.IsNullOrWhiteSpace(resolvedDirectory) && !Path.IsPathRooted(resolvedDirectory))
            {
                resolvedDirectory = Path.GetFullPath(Path.Combine(basePath, resolvedDirectory));
            }

            if (string.IsNullOrWhiteSpace(resolvedDirectory) || string.IsNullOrWhiteSpace(searchPattern) || !_fileSystem.DirectoryExists(resolvedDirectory))
            {
                yield return CreateResolvedImportRecord(originalPath, expandedPath, ImportResolutionKind.Wildcard, false);

                yield break;
            }

            var hasMatches = false;

            foreach (var match in _fileSystem.EnumerateFiles(resolvedDirectory, searchPattern))
            {
                var matchDirectory = Path.GetDirectoryName(match) ?? string.Empty;

                if (!string.Equals(Path.GetFullPath(matchDirectory), resolvedDirectory, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                hasMatches = true;

                yield return CreateResolvedImportRecord(originalPath, Path.GetFullPath(match), ImportResolutionKind.Wildcard, true);
            }

            if (!hasMatches)
            {
                yield return CreateResolvedImportRecord(originalPath, expandedPath, ImportResolutionKind.Wildcard, false);
            }
        }

        /// <summary>
        /// Creates resolved import metadata for an import path.
        /// </summary>
        /// <param name="originalPath">The original import expression.</param>
        /// <param name="resolvedPath">The resolved path or unresolved value.</param>
        /// <param name="resolutionKind">The resolution kind.</param>
        /// <param name="isResolved">A value indicating whether the import was resolved.</param>
        /// <returns>The populated import record.</returns>
        private static ResolvedImportRecord CreateResolvedImportRecord(string originalPath, string resolvedPath, ImportResolutionKind resolutionKind, bool isResolved)
        {
            return new ResolvedImportRecord
            {
                IsResolved     = isResolved,
                IsRisky        = IsRiskyImportPath(resolvedPath),
                OriginalPath   = originalPath,
                ResolvedPath   = resolvedPath,
                ResolutionKind = resolutionKind
            };
        }

        /// <summary>
        /// Determines whether a file should be treated as XML content.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <param name="content">The file content.</param>
        /// <returns><see langword="true"/> when the file appears to be XML; otherwise <see langword="false"/>.</returns>
        private static bool LooksLikeXml(string path, string content)
        {
            var extension = Path.GetExtension(path);

            if (string.Equals(extension, ".props", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".targets", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".proj", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".vbproj", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".fsproj", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return content.TrimStart().StartsWith("<", StringComparison.Ordinal);
        }

        /// <summary>
        /// Normalizes file content for stable hashing.
        /// </summary>
        /// <param name="content">The original file content.</param>
        /// <returns>The normalized content.</returns>
        private static string NormalizeContent(string content)
        {
            return content.Replace("\r\n", "\n").Trim();
        }

        /// <summary>
        /// Computes a SHA256 hash string for the provided value.
        /// </summary>
        /// <param name="value">The input text.</param>
        /// <returns>The lowercase hexadecimal SHA256 hash.</returns>
        private static string Sha256(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);

            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(bytes);
                var builder = new StringBuilder(hash.Length * 2);

                foreach (var hashByte in hash)
                {
                    builder.Append(hashByte.ToString("x2", CultureInfo.InvariantCulture));
                }

                return builder.ToString();
            }
        }

        /// <summary>
        /// Classifies a file path into a known MSBuild file kind.
        /// </summary>
        /// <param name="path">The file path to classify.</param>
        /// <returns>The inferred file kind.</returns>
        private static MsBuildFileKind Classify(string path)
        {
            var extension = Path.GetExtension(path);
            var fileName = Path.GetFileName(path);

            if (string.Equals(fileName, "Directory.Build.props", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".props", StringComparison.OrdinalIgnoreCase))
            {
                return MsBuildFileKind.Props;
            }

            if (string.Equals(fileName, "Directory.Build.targets", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".targets", StringComparison.OrdinalIgnoreCase))
            {
                return MsBuildFileKind.Targets;
            }

            if (string.Equals(extension, ".sln", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".slnx", StringComparison.OrdinalIgnoreCase))
            {
                return MsBuildFileKind.Solution;
            }

            if (string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".vbproj", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".fsproj", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(extension, ".proj", StringComparison.OrdinalIgnoreCase))
            {
                return MsBuildFileKind.Project;
            }

            return MsBuildFileKind.UnknownMsBuildXml;
        }

        /// <summary>
        /// Evaluates all implemented detection rules for a scanned file record.
        /// </summary>
        /// <param name="record">The file record to evaluate.</param>
        /// <returns>The detected findings.</returns>
        private List<Finding> EvaluateRules(MsBuildFileRecord record)
        {
            if (!_fileSystem.FileExists(record.Path))
            {
                return new List<Finding>();
            }

            var content = GetFileContent(record.Path);

            if (!LooksLikeXml(record.Path, content))
            {
                return new List<Finding>();
            }

            var findings = new List<Finding>();

            if (record.HasMarkOfTheWeb)
            {
                findings.Add(CreateFileLevelFinding("MBG011", "Mark-of-the-Web detected", "Project or build file has Mark-of-the-Web metadata.", FindingSeverity.Medium, FindingConfidence.High, record.Path, PolicyAction.RequireApproval, "Require explicit review for downloaded or untrusted-source files."));
            }

            if (record.ParseDiagnostics.Count > 0)
            {
                var diagnostic = record.ParseDiagnostics[0];

                findings.Add(CreateFileLevelFinding("MBG012", "Project parse or analysis issue", "Project file has parse errors or unsupported constructs that prevent full analysis.", FindingSeverity.Medium, FindingConfidence.Medium, record.Path, PolicyAction.Warn, "Fix parse errors and re-scan, or enforce stricter policy for incomplete analysis.", diagnostic.Line, diagnostic.Column));

                return findings;
            }

            if (record.AnalysisStatus == AnalysisStatus.Partial)
            {
                findings.Add(CreateFileLevelFinding("MBG012", "Project parse or analysis issue", "Project file has parse errors or unsupported constructs that prevent full analysis.", FindingSeverity.Medium, FindingConfidence.Medium, record.Path, PolicyAction.Warn, string.IsNullOrWhiteSpace(record.AnalysisSummary) ? "Fix parse errors and re-scan, or enforce stricter policy for incomplete analysis." : record.AnalysisSummary));
            }

            var parsedDocument = GetParsedDocument(record.Path, content);

            if (parsedDocument.ParseException != null || parsedDocument.Document == null)
            {
                var parseException = parsedDocument.ParseException;

                findings.Add(CreateFileLevelFinding("MBG012", "Project parse or analysis issue", "Project file has parse errors or unsupported constructs that prevent full analysis.", FindingSeverity.Medium, FindingConfidence.Medium, record.Path, PolicyAction.Warn, "Fix parse errors and re-scan, or enforce stricter policy for incomplete analysis.", parseException == null ? 0 : parseException.LineNumber, parseException == null ? 0 : parseException.LinePosition));

                return findings;
            }

            var document = parsedDocument.Document;

            findings.AddRange(FindMbg001(document, record.Path));
            findings.AddRange(FindMbg002(document, record.Path));
            findings.AddRange(FindMbg003(document, record.Path));
            findings.AddRange(FindMbg004(document, record.Path));
            findings.AddRange(FindMbg005(document, record.Path));
            findings.AddRange(FindMbg006(document, record.Path));
            findings.AddRange(FindMbg007(document, record.Path));
            findings.AddRange(FindMbg008(document, record.Path));
            findings.AddRange(FindMbg009(document, record));
            findings.AddRange(FindMbg010(record));
            findings.AddRange(FindMbg013(document, record.Path));

            foreach (var finding in findings)
            {
                ApplyFindingMetadata(finding, record);
            }

            return findings;
        }

        /// <summary>
        /// Applies file-derived scoring metadata to a finding.
        /// </summary>
        /// <param name="finding">The finding to update.</param>
        /// <param name="record">The scanned file record.</param>
        private static void ApplyFindingMetadata(Finding finding, MsBuildFileRecord record)
        {
            finding.FileHasMarkOfTheWeb = record.HasMarkOfTheWeb;
            finding.IsInFileImportedByMultipleProjects = record.ImportedByCount > 1;
            finding.IntroducedViaProject = record.IntroducedViaProject;
            finding.IsTransitivePackage = record.IsTransitivePackage;
            finding.NuGetAssetPath = record.NuGetAssetPath;
            finding.PackageAssetKind = record.PackageAssetKind;
            finding.PackageContentHash = record.PackageContentHash;
            finding.PackageId = record.PackageId;
            finding.PackageSignatureState = record.PackageSignatureState;
            finding.PackageSource = record.PackageSource;
            finding.PackageSourceEvidenceKind = record.PackageSourceEvidenceKind;
            finding.PackageSourceEvidencePath = record.PackageSourceEvidencePath;
            finding.PackageVersion = record.PackageVersion;
            finding.SdkIdentifier = record.SdkIdentifier;
            finding.SdkVersion = record.SdkVersion;
            finding.IsPackageSourceInferred = record.IsPackageSourceInferred;
        }

        /// <summary>
        /// Detects rule MBG001: <c>UsingTask</c> contains inline <c>Code</c>.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG001 findings.</returns>
        private static IEnumerable<Finding> FindMbg001(XDocument document, string filePath)
        {
            var usingTasks = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "UsingTask", StringComparison.OrdinalIgnoreCase));

            foreach (var usingTask in usingTasks)
            {
                var codeElement = usingTask.Descendants().FirstOrDefault(element => string.Equals(element.Name.LocalName, "Code", StringComparison.OrdinalIgnoreCase));

                if (codeElement == null)
                {
                    continue;
                }

                yield return CreateFinding("MBG001", "Inline code in UsingTask", "UsingTask contains inline Code.", FindingSeverity.Medium, FindingConfidence.High, filePath, usingTask, PolicyAction.RequireApproval, "Move task logic to a signed external assembly.");
            }
        }

        /// <summary>
        /// Detects rule MBG002: dynamic code task factory usage.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG002 findings.</returns>
        private static IEnumerable<Finding> FindMbg002(XDocument document, string filePath)
        {
            var usingTasks = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "UsingTask", StringComparison.OrdinalIgnoreCase));

            foreach (var usingTask in usingTasks)
            {
                var factory = usingTask.Attribute("TaskFactory")?.Value;

                if (string.IsNullOrWhiteSpace(factory))
                {
                    continue;
                }

                var taskFactory = factory!;

                if (taskFactory.IndexOf("RoslynCodeTaskFactory", StringComparison.OrdinalIgnoreCase) < 0 &&
                    taskFactory.IndexOf("CodeTaskFactory", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    continue;
                }

                yield return CreateFinding("MBG002", "Dynamic task factory usage", "UsingTask uses RoslynCodeTaskFactory or CodeTaskFactory.", FindingSeverity.Medium, FindingConfidence.High, filePath, usingTask, PolicyAction.RequireApproval, "Review the task source and require explicit trust.");
            }
        }

        /// <summary>
        /// Detects rule MBG003: project <c>InitialTargets</c> usage.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG003 findings.</returns>
        private static IEnumerable<Finding> FindMbg003(XDocument document, string filePath)
        {
            var project = document.Root;

            if (project == null)
            {
                yield break;
            }

            var initialTargets = project.Attribute("InitialTargets")?.Value;

            if (string.IsNullOrWhiteSpace(initialTargets))
            {
                yield break;
            }

            yield return CreateFinding("MBG003", "InitialTargets is present", "Project sets InitialTargets which can force early execution.", FindingSeverity.High, FindingConfidence.Medium, filePath, project, PolicyAction.RequireApproval, "Validate intent and compare against baseline.");
        }

        /// <summary>
        /// Detects rule MBG004: early lifecycle target hooks.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG004 findings.</returns>
        private static IEnumerable<Finding> FindMbg004(XDocument document, string filePath)
        {
            var targets = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "Target", StringComparison.OrdinalIgnoreCase));

            foreach (var target in targets)
            {
                var name = target.Attribute("Name")?.Value;
                var beforeTargets = target.Attribute("BeforeTargets")?.Value;
                var hitsEarlyName = string.Equals(name, "BeforeBuild", StringComparison.OrdinalIgnoreCase) || string.Equals(name, "PrepareForBuild", StringComparison.OrdinalIgnoreCase);
                var hooksEarlyTarget = false;

                if (!string.IsNullOrWhiteSpace(beforeTargets))
                {
                    var targetList = beforeTargets!;

                    hooksEarlyTarget = targetList.IndexOf("BeforeBuild", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                       targetList.IndexOf("PrepareForBuild", StringComparison.OrdinalIgnoreCase) >= 0;
                }

                if (!hitsEarlyName && !hooksEarlyTarget)
                {
                    continue;
                }

                yield return CreateFinding("MBG004", "Early lifecycle target hook", "Target participates in early lifecycle build hooks.", FindingSeverity.Medium, FindingConfidence.Medium, filePath, target, PolicyAction.Warn, "Review whether early hook behavior is required.");
            }
        }

        /// <summary>
        /// Detects rule MBG005: shell invocation through <c>Exec</c>.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG005 findings.</returns>
        private static IEnumerable<Finding> FindMbg005(XDocument document, string filePath)
        {
            var execNodes = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "Exec", StringComparison.OrdinalIgnoreCase));

            foreach (var exec in execNodes)
            {
                var command = exec.Attribute("Command")?.Value;

                if (string.IsNullOrWhiteSpace(command))
                {
                    continue;
                }

                var execCommand = command!;

                if (!LooksLikeShellCommand(execCommand))
                {
                    continue;
                }

                yield return CreateFinding("MBG005", "Shell execution through Exec", "Exec command invokes a shell or script host.", FindingSeverity.High, FindingConfidence.High, filePath, exec, PolicyAction.Block, "Block by default unless explicitly approved.");
            }
        }

        /// <summary>
        /// Detects rule MBG006: inline code references process creation APIs.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG006 findings.</returns>
        private IEnumerable<Finding> FindMbg006(XDocument document, string filePath)
        {
            var codeNodes = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "Code", StringComparison.OrdinalIgnoreCase));

            foreach (var codeNode in codeNodes)
            {
                var inlineCode = codeNode.Value;
                var analysis = GetInlineCodeAnalysis(inlineCode);

                if (string.IsNullOrWhiteSpace(inlineCode))
                {
                    continue;
                }

                if (!analysis.UsesProcessCreationApis && !ContainsAnyIndicator(inlineCode, _processCreationIndicators))
                {
                    continue;
                }

                yield return CreateFinding("MBG006", "Inline code process creation", "Inline code references process creation APIs or shell launch indicators.", FindingSeverity.High, FindingConfidence.High, filePath, codeNode, PolicyAction.Block, "Block by default unless explicitly approved by policy.");
            }
        }

        /// <summary>
        /// Detects rule MBG007: inline code references reflection, dynamic loading, or native interop.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG007 findings.</returns>
        private IEnumerable<Finding> FindMbg007(XDocument document, string filePath)
        {
            var codeNodes = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "Code", StringComparison.OrdinalIgnoreCase));

            foreach (var codeNode in codeNodes)
            {
                var inlineCode = codeNode.Value;
                var analysis = GetInlineCodeAnalysis(inlineCode);

                if (string.IsNullOrWhiteSpace(inlineCode))
                {
                    continue;
                }

                if (!analysis.UsesReflectionOrInterop && !ContainsAnyIndicator(inlineCode, _reflectionInteropIndicators))
                {
                    continue;
                }

                yield return CreateFinding("MBG007", "Inline code reflection or interop", "Inline code references reflection, dynamic loading, or native interop indicators.", FindingSeverity.High, FindingConfidence.High, filePath, codeNode, PolicyAction.RequireApproval, "Require explicit review and approval for reflection or native interop usage.");
            }
        }

        /// <summary>
        /// Detects rule MBG008: inline code contains encoded payload indicators.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG008 findings.</returns>
        private IEnumerable<Finding> FindMbg008(XDocument document, string filePath)
        {
            var codeNodes = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "Code", StringComparison.OrdinalIgnoreCase));

            foreach (var codeNode in codeNodes)
            {
                var inlineCode = codeNode.Value;
                var analysis = GetInlineCodeAnalysis(inlineCode);

                if (string.IsNullOrWhiteSpace(inlineCode))
                {
                    continue;
                }

                var containsBase64Blob = Base64LikeRegex.IsMatch(inlineCode);
                var containsByteArrayBlob = inlineCode.IndexOf("new byte[]", StringComparison.OrdinalIgnoreCase) >= 0 && inlineCode.Length > 800;

                if (!analysis.ContainsEncodedPayloadIndicators && !containsBase64Blob && !containsByteArrayBlob)
                {
                    continue;
                }

                yield return CreateFinding("MBG008", "Inline encoded payload indicator", "Inline code contains encoded payload or large embedded byte array indicators.", FindingSeverity.High, FindingConfidence.High, filePath, codeNode, PolicyAction.Block, "Block by default unless payload intent is explicitly reviewed and approved.");
            }
        }

        /// <summary>
        /// Detects rule MBG009: risky import path classification.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG009 findings.</returns>
        private static IEnumerable<Finding> FindMbg009(XDocument document, MsBuildFileRecord record)
        {
            var importNodes = document.Descendants().Where(element => string.Equals(element.Name.LocalName, "Import", StringComparison.OrdinalIgnoreCase));

            foreach (var importNode in importNodes)
            {
                var importPath = importNode.Attribute("Project")?.Value;

                if (string.IsNullOrWhiteSpace(importPath))
                {
                    continue;
                }

                var matchingResolvedImports = record.ResolvedImports
                    .Where(item => string.Equals(item.OriginalPath, importPath, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                var importProjectPath = importPath!;

                if (!TryClassifyImportRisk(importProjectPath, matchingResolvedImports, out var confidence, out var reason, out var resolvedPath))
                {
                    continue;
                }

                var finding = CreateFinding("MBG009", "Risky import path", "Import path resolves to traversal, temporary, user-writable, or remote location indicators.", FindingSeverity.High, confidence, record.Path, importNode, PolicyAction.RequireApproval, "Require review and approval for non-standard import locations.");

                finding.Evidence = string.IsNullOrWhiteSpace(resolvedPath)
                    ? string.Format(CultureInfo.InvariantCulture, "{0} | Risk reason: {1}", finding.Evidence, reason)
                    : string.Format(CultureInfo.InvariantCulture, "{0} | Resolved path: {1} | Risk reason: {2}", finding.Evidence, resolvedPath, reason);
                finding.Fingerprint = Sha256(string.Format(CultureInfo.InvariantCulture, "{0}|{1}|{2}|{3}|{4}", finding.Id, finding.FilePath, finding.StartLine, finding.StartColumn, finding.Evidence));

                yield return finding;
            }
        }

        private static bool TryClassifyImportRisk(string importPath, IList<ResolvedImportRecord> resolvedImports, out FindingConfidence confidence, out string reason, out string resolvedPath)
        {
            confidence = FindingConfidence.Medium;
            reason = string.Empty;
            resolvedPath = string.Empty;

            if (resolvedImports.Count > 0)
            {
                var remoteRecord = resolvedImports.FirstOrDefault(item => item.ResolutionKind == ImportResolutionKind.Remote);

                if (remoteRecord != null)
                {
                    confidence = FindingConfidence.High;
                    reason = "Import resolves to a remote or UNC location.";
                    resolvedPath = remoteRecord.ResolvedPath;

                    return true;
                }

                var unresolvedRecord = resolvedImports.FirstOrDefault(item => item.ResolutionKind == ImportResolutionKind.Unresolved);

                if (unresolvedRecord != null)
                {
                    confidence = FindingConfidence.Medium;
                    reason = "Import could not be statically resolved and is treated conservatively.";
                    resolvedPath = unresolvedRecord.ResolvedPath;

                    return true;
                }

                var unresolvedWildcardRecord = resolvedImports.FirstOrDefault(item => item.ResolutionKind == ImportResolutionKind.Wildcard && !item.IsResolved);

                if (unresolvedWildcardRecord != null)
                {
                    confidence = FindingConfidence.Medium;
                    reason = "Wildcard import did not resolve to concrete files and is treated conservatively.";
                    resolvedPath = unresolvedWildcardRecord.ResolvedPath;

                    return true;
                }

                var riskyResolvedRecord = resolvedImports.FirstOrDefault(item => IsRiskyResolvedImportPath(item.ResolvedPath));

                if (riskyResolvedRecord != null)
                {
                    confidence = FindingConfidence.High;
                    reason = "Resolved import path matches risky location indicators.";
                    resolvedPath = riskyResolvedRecord.ResolvedPath;

                    return true;
                }

                return false;
            }

            if (!IsRiskyImportPath(importPath))
            {
                return false;
            }

            confidence = FindingConfidence.Medium;
            reason = "Import path matched risky raw-text indicators without resolved import metadata.";
            resolvedPath = importPath;

            return true;
        }

        /// <summary>
        /// Detects rule MBG013: blocked assembly reference indicators.
        /// </summary>
        /// <param name="document">The XML document to inspect.</param>
        /// <param name="filePath">The source file path.</param>
        /// <returns>A sequence of MBG013 findings.</returns>
        private IEnumerable<Finding> FindMbg013(XDocument document, string filePath)
        {
            if (_additionalBlockedAssemblies.Length == 0)
            {
                yield break;
            }

            var referenceNodes = document.Descendants()
                .Where(element => string.Equals(element.Name.LocalName, "Reference", StringComparison.OrdinalIgnoreCase));

            foreach (var referenceNode in referenceNodes)
            {
                var includeValue = referenceNode.Attribute("Include")?.Value;

                if (string.IsNullOrWhiteSpace(includeValue))
                {
                    continue;
                }

                var assemblyName = includeValue!;
                var separatorIndex = assemblyName.IndexOf(',');

                if (separatorIndex > 0)
                {
                    assemblyName = assemblyName.Substring(0, separatorIndex);
                }

                assemblyName = assemblyName.Trim();

                if (!_additionalBlockedAssemblies.Contains(assemblyName, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                yield return CreateFinding(
                    "MBG013",
                    "Blocked assembly reference",
                    "Project references an assembly configured as blocked.",
                    FindingSeverity.High,
                    FindingConfidence.High,
                    filePath,
                    referenceNode,
                    PolicyAction.Block,
                    "Remove or replace blocked assembly references, or explicitly approve by policy.");
            }
        }

        private static bool IsRiskyResolvedImportPath(string resolvedPath)
        {
            if (string.IsNullOrWhiteSpace(resolvedPath))
            {
                return false;
            }

            var normalized = resolvedPath.Replace('/', '\\');

            if (normalized.StartsWith("\\\\", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (normalized.IndexOf("\\temp\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("\\tmp\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("%temp%", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("%tmp%", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Detects rule MBG010 for build customization files observed during scanning.
        /// </summary>
        /// <param name="record">The scanned file record.</param>
        /// <returns>A sequence of MBG010 findings.</returns>
        private static IEnumerable<Finding> FindMbg010(MsBuildFileRecord record)
        {
            if (record.FileKind != MsBuildFileKind.Props && record.FileKind != MsBuildFileKind.Targets)
            {
                yield break;
            }

            yield return CreateFileLevelFinding(
                "MBG010",
                "Build customization file detected",
                "A .props or .targets file was discovered during scan and should be reviewed.",
                FindingSeverity.Medium,
                FindingConfidence.Medium,
                record.Path,
                PolicyAction.RequireApproval,
                "Review and approve build customization files before trusting them.");
        }

        /// <summary>
        /// Performs Roslyn-backed static analysis for inline C# code.
        /// </summary>
        /// <param name="inlineCode">The inline code to analyze.</param>
        /// <returns>The analysis result.</returns>
        private static InlineCodeAnalysisResult AnalyzeInlineCode(string inlineCode)
        {
            var result = new InlineCodeAnalysisResult();

            if (string.IsNullOrWhiteSpace(inlineCode))
            {
                return result;
            }

            try
            {
                var syntaxTree = CSharpSyntaxTree.ParseText(inlineCode, RoslynParseOptions);
                var root = syntaxTree.GetRoot();
                result.ParsedSuccessfully = !syntaxTree.GetDiagnostics().Any(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);

                foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    var invocationText = invocation.Expression.ToString();

                    if (LooksLikeProcessCreationInvocation(invocationText))
                    {
                        result.UsesProcessCreationApis = true;
                    }

                    if (LooksLikeReflectionOrInteropInvocation(invocationText))
                    {
                        result.UsesReflectionOrInterop = true;
                    }
                }

                foreach (var objectCreation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
                {
                    var typeText = objectCreation.Type.ToString();

                    if (string.Equals(typeText, "ProcessStartInfo", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(typeText, "System.Diagnostics.ProcessStartInfo", StringComparison.OrdinalIgnoreCase))
                    {
                        result.UsesProcessCreationApis = true;
                    }
                }

                if (root.DescendantNodes().OfType<AttributeSyntax>().Any(attribute => string.Equals(attribute.Name.ToString(), "DllImport", StringComparison.OrdinalIgnoreCase) || string.Equals(attribute.Name.ToString(), "DllImportAttribute", StringComparison.OrdinalIgnoreCase)))
                {
                    result.UsesReflectionOrInterop = true;
                }

                foreach (var literal in root.DescendantNodes().OfType<LiteralExpressionSyntax>())
                {
                    if (!literal.IsKind(SyntaxKind.StringLiteralExpression))
                    {
                        continue;
                    }

                    var literalValue = literal.Token.ValueText;

                    if (Base64LikeRegex.IsMatch(literalValue))
                    {
                        result.ContainsEncodedPayloadIndicators = true;

                        break;
                    }
                }

                if (!result.ContainsEncodedPayloadIndicators)
                {
                    result.ContainsEncodedPayloadIndicators = root.DescendantNodes().OfType<ArrayCreationExpressionSyntax>().Any(arrayCreation =>
                    {
                        var rankSpecifier = arrayCreation.Type.RankSpecifiers.FirstOrDefault();

                        if (rankSpecifier == null || rankSpecifier.Sizes.Count == 0)
                        {
                            return false;
                        }

                        var sizeExpression = rankSpecifier.Sizes[0];

                        return sizeExpression is LiteralExpressionSyntax literalSize &&
                               literalSize.Token.Value is int length &&
                               length >= 128;
                    });
                }
            }
            catch
            {
                return result;
            }

            return result;
        }

        /// <summary>
        /// Clears scan-local caches before a new scan starts.
        /// </summary>
        private void ResetCaches()
        {
            _fileContentCache.Clear();
            _parsedDocumentCache.Clear();
            _inlineCodeAnalysisCache.Clear();
            _packageAssetProvenanceCache.Clear();
            _processedAssetsFiles.Clear();
        }

        /// <summary>
        /// Applies package asset provenance metadata to a scanned file record when available.
        /// </summary>
        /// <param name="record">The file record to update.</param>
        private void ApplyPackageAssetMetadata(MsBuildFileRecord record)
        {
            if (!_packageAssetProvenanceCache.TryGetValue(record.Path, out var provenanceRecord))
            {
                return;
            }

            record.IntroducedViaProject = provenanceRecord.IntroducedViaProject;
            record.IsTransitivePackage = provenanceRecord.IsTransitivePackage;
            record.NuGetAssetPath = provenanceRecord.NuGetAssetPath;
            record.PackageAssetKind = provenanceRecord.AssetKind;
            record.PackageContentHash = provenanceRecord.PackageContentHash;
            record.PackageId = provenanceRecord.PackageId;
            record.PackageSource = provenanceRecord.PackageSource;
            record.PackageSourceEvidenceKind = provenanceRecord.PackageSourceEvidenceKind;
            record.PackageSourceEvidencePath = provenanceRecord.PackageSourceEvidencePath;
            record.PackageVersion = provenanceRecord.PackageVersion;
            record.IsPackageSourceInferred = provenanceRecord.IsPackageSourceInferred;
        }

        /// <summary>
        /// Applies package provenance metadata to a resolved import when available.
        /// </summary>
        /// <param name="resolvedImport">The resolved import to update.</param>
        private void ApplyResolvedImportMetadata(ResolvedImportRecord resolvedImport)
        {
            if (string.IsNullOrWhiteSpace(resolvedImport.ResolvedPath) ||
                !_packageAssetProvenanceCache.TryGetValue(resolvedImport.ResolvedPath, out var provenanceRecord))
            {
                return;
            }

            resolvedImport.IntroducedViaProject = provenanceRecord.IntroducedViaProject;
            resolvedImport.IsTransitivePackage = provenanceRecord.IsTransitivePackage;
            resolvedImport.NuGetAssetPath = provenanceRecord.NuGetAssetPath;
            resolvedImport.PackageAssetKind = provenanceRecord.AssetKind;
            resolvedImport.PackageContentHash = provenanceRecord.PackageContentHash;
            resolvedImport.PackageId = provenanceRecord.PackageId;
            resolvedImport.PackageSource = provenanceRecord.PackageSource;
            resolvedImport.PackageSourceEvidenceKind = provenanceRecord.PackageSourceEvidenceKind;
            resolvedImport.PackageSourceEvidencePath = provenanceRecord.PackageSourceEvidencePath;
            resolvedImport.PackageVersion = provenanceRecord.PackageVersion;
            resolvedImport.IsPackageSourceInferred = provenanceRecord.IsPackageSourceInferred;
        }

        /// <summary>
        /// Applies SDK declaration metadata from the project document to the file record.
        /// </summary>
        /// <param name="document">The parsed project document.</param>
        /// <param name="record">The file record to update.</param>
        private static void ApplySdkMetadata(XDocument document, MsBuildFileRecord record)
        {
            var project = document.Root;

            if (project == null)
            {
                return;
            }

            var sdkAttribute = project.Attribute("Sdk")?.Value;

            if (!string.IsNullOrWhiteSpace(sdkAttribute))
            {
                var sdkValue = sdkAttribute!;

                ApplySdkValue(record, sdkValue);

                return;
            }

            var sdkElement = project.Elements().FirstOrDefault(element => string.Equals(element.Name.LocalName, "Sdk", StringComparison.OrdinalIgnoreCase));

            if (sdkElement == null)
            {
                return;
            }

            record.SdkIdentifier = sdkElement.Attribute("Name")?.Value ?? string.Empty;
            record.SdkVersion = sdkElement.Attribute("Version")?.Value ?? string.Empty;
        }

        /// <summary>
        /// Applies SDK metadata parsed from a project <c>Sdk</c> attribute value.
        /// </summary>
        /// <param name="record">The file record to update.</param>
        /// <param name="sdkValue">The raw SDK attribute value.</param>
        private static void ApplySdkValue(MsBuildFileRecord record, string sdkValue)
        {
            record.SdkIdentifier = sdkValue;

            var firstSdk = sdkValue.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

            if (string.IsNullOrWhiteSpace(firstSdk))
            {
                return;
            }

            var separatorIndex = firstSdk.IndexOf('/');

            if (separatorIndex <= 0 || separatorIndex == firstSdk.Length - 1)
            {
                return;
            }

            record.SdkIdentifier = firstSdk.Substring(0, separatorIndex);
            record.SdkVersion = firstSdk.Substring(separatorIndex + 1);
        }

        /// <summary>
        /// Enqueues restored NuGet package build assets for a scanned project when assets metadata is available.
        /// </summary>
        /// <param name="queue">The discovery queue.</param>
        /// <param name="queued">The queued-path tracker.</param>
        /// <param name="record">The scanned file record.</param>
        private void EnqueuePackageAssetCandidates(Queue<DiscoveryCandidate> queue, HashSet<string> queued, MsBuildFileRecord record)
        {
            if (record.FileKind != MsBuildFileKind.Project)
            {
                return;
            }

            LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: checking assets for project {0}", record.Path));

            var assetsFilePath = GetAssetsFilePath(record.Path);

            if (string.IsNullOrWhiteSpace(assetsFilePath))
            {
                LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: skipped project {0} because assets path could not be resolved.", record.Path));
                return;
            }

            var assetsFileExists = false;

            try
            {
                assetsFileExists = _fileSystem.FileExists(assetsFilePath);
            }
            catch
            {
                LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: failed to check assets file existence for {0}", assetsFilePath));
                return;
            }

            if (!assetsFileExists)
            {
                LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: no assets file found at {0}", assetsFilePath));
                return;
            }

            if (!_processedAssetsFiles.Add(assetsFilePath))
            {
                LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: assets file already processed {0}", assetsFilePath));
                return;
            }

            LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: parsing assets file {0}", assetsFilePath));

            var assetsContent = GetFileContent(assetsFilePath);
            IReadOnlyList<PackageAssetProvenanceRecord> provenanceRecords;

            try
            {
                provenanceRecords = _packageAssetsFileParser.ParseContent(assetsContent);
            }
            catch (Exception ex)
            {
                MarkPartialAnalysis(record, string.Format(System.Globalization.CultureInfo.InvariantCulture, "Package assets metadata could not be parsed from {0}: {1}", assetsFilePath, ex.Message));
                LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: failed parsing assets file {0}: {1}", assetsFilePath, ex.Message));
                return;
            }

            var totalRecords = provenanceRecords.Count;
            var processedRecords = 0;

            LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: discovered {0} package asset records in {1}", totalRecords, assetsFilePath));

            foreach (var provenanceRecord in provenanceRecords)
            {
                processedRecords++;

                if (string.IsNullOrWhiteSpace(provenanceRecord.NuGetAssetPath) ||
                    !IsSupportedMsBuildPath(provenanceRecord.NuGetAssetPath))
                {
                    LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: [{0}/{1}] skipped unsupported package asset path.", processedRecords, totalRecords));
                    continue;
                }

                var packageId = string.IsNullOrWhiteSpace(provenanceRecord.PackageId) ? "<unknown>" : provenanceRecord.PackageId;
                var packageVersion = string.IsNullOrWhiteSpace(provenanceRecord.PackageVersion) ? "<unknown>" : provenanceRecord.PackageVersion;

                LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: [{0}/{1}] resolving provenance for {2} {3}", processedRecords, totalRecords, packageId, packageVersion));

                var attribution = _packageProvenanceResolver.Resolve(
                    record.Path,
                    assetsFilePath,
                    provenanceRecord.PackageId,
                    provenanceRecord.PackageVersion,
                    provenanceRecord.NuGetAssetPath);

                provenanceRecord.PackageSource = attribution.Source;
                provenanceRecord.PackageSourceEvidenceKind = attribution.EvidenceKind;
                provenanceRecord.PackageSourceEvidencePath = attribution.EvidencePath;
                provenanceRecord.PackageContentHash = string.IsNullOrWhiteSpace(provenanceRecord.PackageContentHash)
                    ? attribution.ContentHash
                    : provenanceRecord.PackageContentHash;
                provenanceRecord.IsPackageSourceInferred = attribution.IsInferred;

                _packageAssetProvenanceCache[provenanceRecord.NuGetAssetPath] = provenanceRecord;

                if (!_fileSystem.FileExists(provenanceRecord.NuGetAssetPath))
                {
                    LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: [{0}/{1}] asset file not found for {2} {3}", processedRecords, totalRecords, packageId, packageVersion));
                    continue;
                }

                EnqueueCandidate(queue, queued, provenanceRecord.NuGetAssetPath, FileDiscoverySource.NuGetPackageAsset);
                LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: [{0}/{1}] queued asset {2}", processedRecords, totalRecords, provenanceRecord.NuGetAssetPath));
            }

            LogActivity(string.Format(CultureInfo.InvariantCulture, "NuGet scan: completed assets processing for {0}", record.Path));
        }

        private static void MarkPartialAnalysis(MsBuildFileRecord record, string summary)
        {
            if (record.AnalysisStatus == AnalysisStatus.Failed)
            {
                return;
            }

            record.AnalysisStatus = AnalysisStatus.Partial;

            if (string.IsNullOrWhiteSpace(record.AnalysisSummary))
            {
                record.AnalysisSummary = summary;

                return;
            }

            if (!record.AnalysisSummary.Contains(summary, StringComparison.OrdinalIgnoreCase))
            {
                record.AnalysisSummary = string.Concat(record.AnalysisSummary, " ", summary);
            }
        }

        /// <summary>
        /// Writes an activity message through the configured scanner callback when available.
        /// </summary>
        /// <param name="message">The activity message.</param>
        private void LogActivity(string message)
        {
            if (string.IsNullOrWhiteSpace(message))
            {
                return;
            }

            _activityLogger?.Invoke(message);
        }

        /// <summary>
        /// Gets the restored assets file path for a project when it uses the default restore layout.
        /// </summary>
        /// <param name="projectPath">The project file path.</param>
        /// <returns>The expected assets file path.</returns>
        private static string GetAssetsFilePath(string projectPath)
        {
            var projectDirectory = Path.GetDirectoryName(projectPath);

            if (string.IsNullOrWhiteSpace(projectDirectory))
            {
                return string.Empty;
            }

            return Path.Combine(projectDirectory, "obj", "project.assets.json");
        }

        /// <summary>
        /// Gets cached file content for a path.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns>The file content.</returns>
        private string GetFileContent(string path)
        {
            if (_fileContentCache.TryGetValue(path, out var content))
            {
                return content;
            }

            content = _fileSystem.ReadAllText(path);
            _fileContentCache[path] = content;

            return content;
        }

        /// <summary>
        /// Gets a cached XML parse result for a file.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <param name="content">The file content.</param>
        /// <returns>The cached parse result.</returns>
        private ParsedDocumentCacheEntry GetParsedDocument(string path, string content)
        {
            if (_parsedDocumentCache.TryGetValue(path, out var cachedEntry))
            {
                return cachedEntry;
            }

            var entry = new ParsedDocumentCacheEntry();

            try
            {
                entry.Document = XDocument.Parse(content, LoadOptions.SetLineInfo | LoadOptions.PreserveWhitespace);
            }
            catch (XmlException xmlException)
            {
                entry.ParseException = xmlException;
            }

            _parsedDocumentCache[path] = entry;

            return entry;
        }

        /// <summary>
        /// Gets cached inline-code analysis for the provided code.
        /// </summary>
        /// <param name="inlineCode">The inline code to analyze.</param>
        /// <returns>The cached analysis result.</returns>
        private InlineCodeAnalysisResult GetInlineCodeAnalysis(string inlineCode)
        {
            if (_inlineCodeAnalysisCache.TryGetValue(inlineCode, out var cachedResult))
            {
                return cachedResult;
            }

            var analysisResult = AnalyzeInlineCode(inlineCode);
            _inlineCodeAnalysisCache[inlineCode] = analysisResult;

            return analysisResult;
        }

        /// <summary>
        /// Determines whether an invocation expression represents process creation.
        /// </summary>
        /// <param name="invocationText">The invocation expression text.</param>
        /// <returns><see langword="true"/> when the invocation represents process creation; otherwise <see langword="false"/>.</returns>
        private static bool LooksLikeProcessCreationInvocation(string invocationText)
        {
            return string.Equals(invocationText, "Process.Start", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(invocationText, "System.Diagnostics.Process.Start", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(invocationText, "CreateProcess", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether an invocation expression represents reflection or interop behavior.
        /// </summary>
        /// <param name="invocationText">The invocation expression text.</param>
        /// <returns><see langword="true"/> when the invocation represents reflection or interop behavior; otherwise <see langword="false"/>.</returns>
        private static bool LooksLikeReflectionOrInteropInvocation(string invocationText)
        {
            return string.Equals(invocationText, "Assembly.Load", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(invocationText, "System.Reflection.Assembly.Load", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(invocationText, "Activator.CreateInstance", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(invocationText, "Marshal.GetDelegateForFunctionPointer", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(invocationText, "LoadLibrary", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether an import path has risky trust indicators.
        /// </summary>
        /// <param name="importPath">Import path value.</param>
        /// <returns><see langword="true"/> when the path has risky indicators; otherwise <see langword="false"/>.</returns>
        private static bool IsRiskyImportPath(string importPath)
        {
            if (string.IsNullOrWhiteSpace(importPath))
            {
                return false;
            }

            var normalized = importPath.Replace('/', '\\');

            if (normalized.StartsWith("..\\", StringComparison.OrdinalIgnoreCase) ||
                normalized.IndexOf("\\..\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            if (normalized.StartsWith("\\\\", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (normalized.IndexOf("\\temp\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("\\tmp\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("%temp%", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("%tmp%", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            if (normalized.IndexOf("\\users\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                normalized.IndexOf("%userprofile%", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Determines whether a path should be scanned as an MSBuild-sensitive file.
        /// </summary>
        /// <param name="path">The file path to evaluate.</param>
        /// <returns><see langword="true"/> when the path is an MSBuild-sensitive file; otherwise <see langword="false"/>.</returns>
        private bool IsSupportedMsBuildPath(string path)
        {
            var extension = Path.GetExtension(path);
            var fileName = Path.GetFileName(path);

            if (string.Equals(fileName, "Directory.Build.props", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fileName, "Directory.Build.targets", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return _msBuildExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Normalizes configured file extensions for case-insensitive matching.
        /// </summary>
        /// <param name="values">Optional configured extension values.</param>
        /// <param name="fallback">Fallback extension values.</param>
        /// <returns>The normalized extension list.</returns>
        private static string[] NormalizeExtensions(IEnumerable<string>? values, IEnumerable<string> fallback)
        {
            var normalized = NormalizeValues(values, fallback)
                .Select(value => value.StartsWith(".", StringComparison.Ordinal) ? value : string.Concat(".", value))
                .ToArray();

            return normalized;
        }

        /// <summary>
        /// Normalizes configured token values and applies fallback values when none are configured.
        /// </summary>
        /// <param name="values">Optional configured values.</param>
        /// <param name="fallback">Fallback values.</param>
        /// <returns>The normalized values.</returns>
        private static string[] NormalizeValues(IEnumerable<string>? values, IEnumerable<string> fallback)
        {
            var source = values ?? fallback;

            var normalized = source
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (normalized.Length == 0)
            {
                return fallback
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Select(value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }

            return normalized;
        }

        /// <summary>
        /// Applies overall analysis status information to the report from file-level records.
        /// </summary>
        /// <param name="report">The report to update.</param>
        private static void ApplyAnalysisStatus(ScanReport report)
        {
            var failedCount = report.FilesScanned.Count(file => file.AnalysisStatus == AnalysisStatus.Failed);
            var partialCount = report.FilesScanned.Count(file => file.AnalysisStatus == AnalysisStatus.Partial);

            if (failedCount > 0)
            {
                report.AnalysisStatus = AnalysisStatus.Failed;
                report.AnalysisSummary = string.Format(CultureInfo.InvariantCulture, "Analysis failed for {0} file(s).", failedCount);

                return;
            }

            if (partialCount > 0)
            {
                report.AnalysisStatus = AnalysisStatus.Partial;
                report.AnalysisSummary = string.Format(CultureInfo.InvariantCulture, "Analysis was partial for {0} file(s).", partialCount);

                return;
            }

            report.AnalysisStatus = AnalysisStatus.Complete;
            report.AnalysisSummary = "Analysis completed successfully.";
        }

        /// <summary>
        /// Determines whether an <c>Exec</c> command string appears to invoke a shell or script host.
        /// </summary>
        /// <param name="command">The command text.</param>
        /// <returns><see langword="true"/> when the command matches shell indicators; otherwise <see langword="false"/>.</returns>
        private static bool LooksLikeShellCommand(string command)
        {
            var value = command.ToLowerInvariant();

            return value.Contains("powershell") ||
                   value.Contains("pwsh") ||
                   value.Contains("cmd.exe") ||
                   value.Contains("cmd /c") ||
                   value.Contains("bash") ||
                   value.Contains("sh ") ||
                   value.Contains("wscript") ||
                   value.Contains("cscript");
        }

        /// <summary>
        /// Determines whether content contains any indicator token.
        /// </summary>
        /// <param name="content">Content to inspect.</param>
        /// <param name="indicators">Indicators to match.</param>
        /// <returns><see langword="true"/> when any indicator exists; otherwise <see langword="false"/>.</returns>
        private static bool ContainsAnyIndicator(string content, IEnumerable<string> indicators)
        {
            foreach (var indicator in indicators)
            {
                if (content.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Creates a file-level finding when XML node location is unavailable.
        /// </summary>
        /// <param name="id">The rule identifier.</param>
        /// <param name="title">The finding title.</param>
        /// <param name="description">The finding description.</param>
        /// <param name="severity">The finding severity.</param>
        /// <param name="confidence">The finding confidence.</param>
        /// <param name="filePath">The source file path.</param>
        /// <param name="action">The default policy action.</param>
        /// <param name="recommendation">Recommendation text.</param>
        /// <param name="line">Optional line number.</param>
        /// <param name="column">Optional column number.</param>
        /// <returns>The created finding.</returns>
        private static Finding CreateFileLevelFinding(string id, string title, string description, FindingSeverity severity, FindingConfidence confidence, string filePath, PolicyAction action, string recommendation, int line = 0, int column = 0)
        {
            var finding = new Finding
            {
                Confidence     = confidence,
                Description    = description,
                Evidence       = string.Empty,
                FilePath       = filePath,
                Id             = id,
                PolicyAction   = action,
                PolicyEvaluatedAction = action,
                Recommendation = recommendation,
                ScannerPolicyAction = action,
                Severity       = severity,
                StartColumn    = column,
                StartLine      = line,
                Title          = title
            };

            finding.Fingerprint = Sha256(string.Format(CultureInfo.InvariantCulture, "{0}|{1}|{2}|{3}|{4}", finding.Id, finding.FilePath, finding.StartLine, finding.StartColumn, finding.Description));

            return finding;
        }

        /// <summary>
        /// Creates a finding instance from rule metadata and XML node location.
        /// </summary>
        /// <param name="id">The rule identifier.</param>
        /// <param name="title">The finding title.</param>
        /// <param name="description">The finding description.</param>
        /// <param name="severity">The finding severity.</param>
        /// <param name="confidence">The finding confidence.</param>
        /// <param name="filePath">The source file path.</param>
        /// <param name="node">The XML node used for evidence and location.</param>
        /// <param name="action">The default policy action.</param>
        /// <param name="recommendation">The recommendation text.</param>
        /// <returns>The created finding.</returns>
        private static Finding CreateFinding(string id, string title, string description, FindingSeverity severity, FindingConfidence confidence, string filePath, XElement node, PolicyAction action, string recommendation)
        {
            var lineInfo = (IXmlLineInfo)node;

            var finding = new Finding
            {
                Confidence     = confidence,
                Description    = description,
                Evidence       = node.ToString(SaveOptions.DisableFormatting),
                FilePath       = filePath,
                Id             = id,
                PolicyAction   = action,
                PolicyEvaluatedAction = action,
                Recommendation = recommendation,
                ScannerPolicyAction = action,
                Severity       = severity,
                StartColumn    = lineInfo.HasLineInfo() ? lineInfo.LinePosition : 0,
                StartLine      = lineInfo.HasLineInfo() ? lineInfo.LineNumber : 0,
                Title          = title
            };

            finding.Fingerprint = Sha256(string.Format(CultureInfo.InvariantCulture, "{0}|{1}|{2}|{3}|{4}", finding.Id, finding.FilePath, finding.StartLine, finding.StartColumn, finding.Evidence));

            return finding;
        }
    }
}
