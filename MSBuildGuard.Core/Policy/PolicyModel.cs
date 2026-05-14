using System;
using System.Collections.Generic;

namespace MSBuildGuard.Core.Policy
{
	/// <summary>
	/// Represents policy configuration for scan and enforcement behavior.
	/// </summary>
	public sealed class PolicyDocument
	{
		/// <summary>
		/// Gets or sets schema version.
		/// </summary>
		public int Version { get; set; } = 1;

		/// <summary>
		/// Gets or sets policy mode.
		/// </summary>
		public string Mode { get; set; } = "warn";

		/// <summary>
		/// Gets or sets a value indicating whether baseline is required.
		/// </summary>
		public bool BaselineRequired { get; set; }

		/// <summary>
		/// Gets or sets a value indicating whether incomplete analysis should be treated strictly.
		/// </summary>
		public bool StrictMode { get; set; }

		/// <summary>
		/// Gets or sets the minimum action to apply when analysis is incomplete.
		/// </summary>
		public PolicyAction IncompleteAnalysisAction { get; set; } = PolicyAction.Warn;

		/// <summary>
		/// Gets or sets the minimum action to apply when a package build asset originates from an unapproved source.
		/// </summary>
		public PolicyAction UnapprovedPackageSourceAction { get; set; } = PolicyAction.RequireApproval;

		/// <summary>
		/// Gets minimum action requirements by severity.
		/// </summary>
		public IDictionary<FindingSeverity, PolicyAction> MinimumActionBySeverity { get; } = new Dictionary<FindingSeverity, PolicyAction>();

		/// <summary>
		/// Gets explicit action overrides by rule id.
		/// </summary>
		public IDictionary<string, PolicyRuleSetting> Rules { get; } = new Dictionary<string, PolicyRuleSetting>(StringComparer.OrdinalIgnoreCase);

		/// <summary>
		/// Gets include file patterns.
		/// </summary>
		public IList<string> Include { get; } = new List<string>();

		/// <summary>
		/// Gets exclude file patterns.
		/// </summary>
		public IList<string> Exclude { get; } = new List<string>();

		/// <summary>
		/// Gets the allowed package source labels or URLs.
		/// </summary>
		public IList<string> AllowedPackageSources { get; } = new List<string>();

		/// <summary>
		/// Gets the blocked package source labels or URLs.
		/// </summary>
		public IList<string> BlockedPackageSources { get; } = new List<string>();
	}

	/// <summary>
	/// Represents per-rule policy settings.
	/// </summary>
	public sealed class PolicyRuleSetting
	{
		/// <summary>
		/// Gets or sets policy action for this rule.
		/// </summary>
		public PolicyAction Action { get; set; }
	}
}
