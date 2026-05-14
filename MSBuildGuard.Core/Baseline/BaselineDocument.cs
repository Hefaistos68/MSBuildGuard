using System;
using System.Collections.Generic;

namespace MSBuildGuard.Core.Baseline
{
	/// <summary>
	/// Represents a persisted baseline snapshot.
	/// </summary>
	public sealed class BaselineDocument
	{
		/// <summary>
		/// Gets or sets schema version.
		/// </summary>
		public int Version { get; set; } = 1;

		/// <summary>
		/// Gets or sets scanner version used to create this baseline.
		/// </summary>
		public string ScannerVersion { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets policy version identifier.
		/// </summary>
		public string PolicyVersion { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the baseline creation timestamp.
		/// </summary>
		public DateTimeOffset CreatedAtUtc { get; set; }

		/// <summary>
		/// Gets or sets optional reviewer identity.
		/// </summary>
		public string ReviewerIdentity { get; set; } = string.Empty;

		/// <summary>
		/// Gets file hash entries tracked by baseline.
		/// </summary>
		public IList<BaselineFileEntry> Files { get; set; } = new List<BaselineFileEntry>();

		/// <summary>
		/// Gets finding fingerprint entries approved by baseline.
		/// </summary>
		public IList<BaselineFindingEntry> ApprovedFindings { get; set; } = new List<BaselineFindingEntry>();
	}

	/// <summary>
	/// Represents a file hash entry in a baseline.
	/// </summary>
	public sealed class BaselineFileEntry
	{
		/// <summary>
		/// Gets or sets file path.
		/// </summary>
		public string Path { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets normalized file content hash.
		/// </summary>
		public string NormalizedSha256 { get; set; } = string.Empty;
	}

	/// <summary>
	/// Represents an approved finding entry in a baseline.
	/// </summary>
	public sealed class BaselineFindingEntry
	{
		/// <summary>
		/// Gets or sets finding fingerprint.
		/// </summary>
		public string Fingerprint { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets finding rule identifier.
		/// </summary>
		public string RuleId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets finding severity at approval time.
		/// </summary>
		public FindingSeverity Severity { get; set; }
	}
}
