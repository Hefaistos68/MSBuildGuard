using System;
using System.Collections.Generic;
using System.Linq;

namespace MSBuildGuard.Core.Baseline
{
	/// <summary>
	/// Compares scan reports with baseline documents.
	/// </summary>
	public sealed class BaselineComparer
	{
		/// <summary>
		/// Compares a report with a baseline and returns comparison details.
		/// </summary>
		/// <param name="report">The scan report.</param>
		/// <param name="baseline">The baseline document.</param>
		/// <returns>The comparison result.</returns>
		public BaselineComparisonResult Compare(ScanReport report, BaselineDocument baseline)
		{
			if (report == null)
			{
				throw new ArgumentNullException(nameof(report));
			}

			if (baseline == null)
			{
				throw new ArgumentNullException(nameof(baseline));
			}

			var baselineFileMap = baseline.Files.ToDictionary(item => item.Path, item => item.NormalizedSha256, StringComparer.OrdinalIgnoreCase);
			var baselineFingerprints = new HashSet<string>(baseline.ApprovedFindings.Select(item => item.Fingerprint), StringComparer.OrdinalIgnoreCase);
			var comparison = new BaselineComparisonResult
			{
				HasBaseline = true
			};

			foreach (var file in report.FilesScanned)
			{
				if (!baselineFileMap.TryGetValue(file.Path, out var hash))
				{
					comparison.NewFiles.Add(FormatDriftPath(file));

					continue;
				}

				if (!string.Equals(hash, file.NormalizedSha256, StringComparison.OrdinalIgnoreCase))
				{
					comparison.ChangedFiles.Add(FormatDriftPath(file));
				}
			}

			foreach (var baselineFile in baseline.Files)
			{
				if (!report.FilesScanned.Any(item => string.Equals(item.Path, baselineFile.Path, StringComparison.OrdinalIgnoreCase)))
				{
					comparison.RemovedFiles.Add(baselineFile.Path);
				}
			}

			foreach (var finding in report.Findings)
			{
				if (string.IsNullOrWhiteSpace(finding.Fingerprint))
				{
					finding.IsNewComparedWithBaseline = true;
					comparison.NewFindings.Add(finding);

					continue;
				}

				if (!baselineFingerprints.Contains(finding.Fingerprint))
				{
					finding.IsNewComparedWithBaseline = true;
					comparison.NewFindings.Add(finding);
				}
			}

			AddMbg003ChangedFindings(report, baselineFileMap, baselineFingerprints, comparison);

			if (comparison.NewFiles.Any(path => path.EndsWith(".props", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".targets", StringComparison.OrdinalIgnoreCase)))
			{
				foreach (var path in comparison.NewFiles.Where(value => value.EndsWith(".props", StringComparison.OrdinalIgnoreCase) || value.EndsWith(".targets", StringComparison.OrdinalIgnoreCase)))
				{
					if (report.Findings.Any(finding =>
						string.Equals(finding.Id, "MBG010", StringComparison.OrdinalIgnoreCase) &&
						string.Equals(finding.FilePath, path, StringComparison.OrdinalIgnoreCase)))
					{
						continue;
					}

					comparison.NewFindings.Add(CreateMbg010Finding(path));
				}
			}

			comparison.DriftDetected = comparison.NewFiles.Count > 0 ||
									   comparison.ChangedFiles.Count > 0 ||
									   comparison.RemovedFiles.Count > 0 ||
									   comparison.NewFindings.Count > 0;
			comparison.Summary = comparison.DriftDetected
				? string.Format(System.Globalization.CultureInfo.InvariantCulture, "Drift detected: {0} new files, {1} changed files, {2} removed files, {3} new findings.", comparison.NewFiles.Count, comparison.ChangedFiles.Count, comparison.RemovedFiles.Count, comparison.NewFindings.Count)
				: "No drift detected.";

			report.BaselineComparison = new BaselineComparisonSummary
			{
				DriftDetected = comparison.DriftDetected,
				HasBaseline   = true,
				Summary       = comparison.Summary
			};

			return comparison;
		}

		/// <summary>
		/// Creates a deterministic MBG010 baseline-drift finding.
		/// </summary>
		/// <param name="path">The new .props or .targets file path.</param>
		/// <returns>The populated MBG010 finding.</returns>
		private static Finding CreateMbg010Finding(string path)
		{
			var finding = new Finding
			{
				Confidence                = FindingConfidence.High,
				Description               = "New .props or .targets file appears compared with baseline.",
				FilePath                  = path,
				Id                        = "MBG010",
				IsNewComparedWithBaseline = true,
				IsNewInBaseline           = true,
				PolicyAction              = PolicyAction.RequireApproval,
				PolicyEvaluatedAction     = PolicyAction.RequireApproval,
				Recommendation            = "Review and approve new build customization files before trusting baseline drift.",
				ScannerPolicyAction       = PolicyAction.RequireApproval,
				Severity                  = FindingSeverity.Medium,
				Title                     = "New build customization file detected"
			};

			finding.Fingerprint = string.Format(System.Globalization.CultureInfo.InvariantCulture, "MBG010|{0}", path);

			return finding;
		}

		/// <summary>
		/// Returns a user-friendly representation of a file for drift reporting, including package asset details when available.
		/// </summary>
		/// <param name="file">The file record to format.</param>
		/// <returns>A formatted string representing the file for drift reporting.</returns>
		private static string FormatDriftPath(MsBuildFileRecord file)
		{
			if (file.PackageAssetKind == PackageAssetKind.Unknown || string.IsNullOrWhiteSpace(file.PackageId))
			{
				return file.Path;
			}

			return string.Format(System.Globalization.CultureInfo.InvariantCulture, "NuGet package asset: {0} {1} ({2}) -> {3}", file.PackageId, file.PackageVersion, file.PackageAssetKind, file.Path);
		}

		/// <summary>
		///	Adds MBG003_CHANGED findings to the comparison result for files that are present in the baseline but have changed content and associated MBG003 findings, indicating potential drift in InitialTargets behavior that may require attention.
		/// </summary>
		/// <param name="report">The scan report containing findings and file records.</param>
		/// <param name="baselineFileMap">A map of file paths to their baseline hashes.</param>
		/// <param name="baselineFingerprints">A set of baseline fingerprints.</param>
		/// <param name="comparison">The baseline comparison result to update with new findings.</param>
		private static void AddMbg003ChangedFindings(ScanReport report, IDictionary<string, string> baselineFileMap, ISet<string> baselineFingerprints, BaselineComparisonResult comparison)
		{
			foreach (var finding in report.Findings)
			{
				if (!string.Equals(finding.Id, "MBG003", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				if (string.IsNullOrWhiteSpace(finding.FilePath))
				{
					continue;
				}

				if (!baselineFileMap.TryGetValue(finding.FilePath, out var baselineHash))
				{
					continue;
				}

				var currentFile = report.FilesScanned.FirstOrDefault(file => string.Equals(file.Path, finding.FilePath, StringComparison.OrdinalIgnoreCase));

				if (currentFile == null)
				{
					continue;
				}

				if (string.Equals(currentFile.NormalizedSha256, baselineHash, StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				if (string.IsNullOrWhiteSpace(finding.Fingerprint) || baselineFingerprints.Contains(finding.Fingerprint))
				{
					continue;
				}

				comparison.NewFindings.Add(CreateMbg003ChangedFinding(finding));
			}
		}

		/// <summary>
		/// Creates a new finding based on an existing MBG003 finding, indicating that the InitialTargets behavior appears changed from baseline for an existing file, which may require attention and approval.
		/// </summary>
		/// <param name="source">The source finding to base the new finding on.</param>
		/// <returns>A new finding indicating a change in InitialTargets behavior.</returns>
		private static Finding CreateMbg003ChangedFinding(Finding source)
		{
			var changedFinding = new Finding
			{
				Confidence                = FindingConfidence.High,
				Description               = "InitialTargets behavior appears changed from baseline for an existing file.",
				EndColumn                 = source.EndColumn,
				EndLine                   = source.EndLine,
				Evidence                  = source.Evidence,
				FilePath                  = source.FilePath,
				Id                        = "MBG003_CHANGED",
				IsNewComparedWithBaseline = true,
				PolicyAction              = PolicyAction.Block,
				PolicyEvaluatedAction     = PolicyAction.Block,
				Recommendation            = "Review InitialTargets drift and require explicit approval before trusting this change.",
				ScannerPolicyAction       = PolicyAction.Block,
				Severity                  = FindingSeverity.High,
				StartColumn               = source.StartColumn,
				StartLine                 = source.StartLine,
				Title                     = "InitialTargets changed from baseline"
			};

			changedFinding.Fingerprint = string.Format(System.Globalization.CultureInfo.InvariantCulture, "MBG003_CHANGED|{0}|{1}", source.FilePath, source.Fingerprint);

			return changedFinding;
		}
	}

	/// <summary>
	/// Represents baseline comparison output.
	/// </summary>
	public sealed class BaselineComparisonResult
	{
		/// <summary>
		/// Gets or sets a value indicating whether a baseline was available.
		/// </summary>
		public bool HasBaseline { get; set; }

		/// <summary>
		/// Gets or sets a value indicating whether drift was detected.
		/// </summary>
		public bool DriftDetected { get; set; }

		/// <summary>
		/// Gets or sets summary text.
		/// </summary>
		public string Summary { get; set; } = string.Empty;

		/// <summary>
		/// Gets newly observed files.
		/// </summary>
		public IList<string> NewFiles { get; } = new List<string>();

		/// <summary>
		/// Gets changed files.
		/// </summary>
		public IList<string> ChangedFiles { get; } = new List<string>();

		/// <summary>
		/// Gets removed files.
		/// </summary>
		public IList<string> RemovedFiles { get; } = new List<string>();

		/// <summary>
		/// Gets findings not present in baseline approval set.
		/// </summary>
		public IList<Finding> NewFindings { get; } = new List<Finding>();
	}
}
