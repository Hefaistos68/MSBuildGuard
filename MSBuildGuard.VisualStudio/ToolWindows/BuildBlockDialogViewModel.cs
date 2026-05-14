using System.Collections.Generic;
using System.IO;
using System.Linq;
using MSBuildGuard.Core;
using MSBuildGuard.VisualStudio.Services;

namespace MSBuildGuard.VisualStudio.ToolWindows
{
	/// <summary>
	/// View model for the build block confirmation dialog.
	/// </summary>
	public sealed class BuildBlockDialogViewModel
	{
		/// <summary>
		/// Represents a single actionable finding row in the dialog grid.
		/// </summary>
		public sealed class FindingRow
		{
			/// <summary>Gets the rule identifier.</summary>
			public string RuleId { get; set; } = string.Empty;

			/// <summary>Gets the finding title.</summary>
			public string Title { get; set; } = string.Empty;

			/// <summary>Gets the severity label.</summary>
			public string Severity { get; set; } = string.Empty;

			/// <summary>Gets the required policy action label.</summary>
			public string Action { get; set; } = string.Empty;

			/// <summary>Gets the short display path of the affected file.</summary>
			public string FilePath { get; set; } = string.Empty;
		}

		/// <summary>
		/// Gets the scan target path.
		/// </summary>
		public string TargetPath { get; }

		/// <summary>
		/// Gets the redacted scan target path for UI display.
		/// </summary>
		public string TargetPathDisplay
		{
			get
			{
				return PathRedactionService.RedactPath(this.TargetPath);
			}
		}

		/// <summary>
		/// Gets the aggregate risk score.
		/// </summary>
		public int RiskScore { get; }

		/// <summary>
		/// Gets the recommended action label.
		/// </summary>
		public string RecommendedAction { get; }

		/// <summary>
		/// Gets the list of actionable findings to display.
		/// </summary>
		public IReadOnlyList<FindingRow> Findings { get; }

		/// <summary>
		/// Initializes a new instance of the <see cref="BuildBlockDialogViewModel"/> class from a scan report.
		/// </summary>
		/// <param name="report">The scan report that triggered the build block.</param>
		public BuildBlockDialogViewModel(ScanReport report)
		{
			this.TargetPath      = report.Target.TargetPath;
			this.RiskScore       = report.RiskScore;
			this.RecommendedAction = report.RecommendedAction.ToString();

			this.Findings = report.Findings
				.Where(f => f.PolicyEvaluatedAction != PolicyAction.Allow)
				.Select(f => new FindingRow
				{
					RuleId   = f.Id,
					Title    = f.Title,
					Severity = f.Severity.ToString(),
					Action   = f.PolicyEvaluatedAction.ToString(),
					FilePath = string.IsNullOrWhiteSpace(f.FilePath)
						? string.Empty
						: Path.GetFileName(f.FilePath)
				})
				.ToList();
		}
	}
}
