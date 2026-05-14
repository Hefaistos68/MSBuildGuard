using System;
using System.Collections.Generic;

namespace MSBuildGuard.Core.Trust
{
	/// <summary>
	/// Represents the supported trust scope values.
	/// </summary>
	public enum TrustDecisionScopeKind
	{
		Unknown,
		File,
		Repository,
		Solution,
		Finding,
		Baseline
	}

	/// <summary>
	/// Represents the supported trust decision values.
	/// </summary>
	public enum TrustDecisionKind
	{
		Unknown,
		Trust,
		TrustUntilChanged,
		Deny,
		DismissFinding
	}

	/// <summary>
	/// Represents persisted trust decision entries.
	/// </summary>
	public sealed class TrustStoreDocument
	{
		/// <summary>
		/// Gets or sets schema version.
		/// </summary>
		public int Version { get; set; } = 1;

		/// <summary>
		/// Gets trust decisions.
		/// </summary>
		public IList<TrustDecisionEntry> Decisions { get; set; } = new List<TrustDecisionEntry>();
	}

	/// <summary>
	/// Represents one append-only trust audit event.
	/// </summary>
	public sealed class TrustAuditEvent
	{
		/// <summary>
		/// Gets or sets the unique audit event identifier.
		/// </summary>
		public string EventId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the event kind.
		/// </summary>
		public string EventKind { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the event timestamp.
		/// </summary>
		public DateTimeOffset OccurredAtUtc { get; set; }

		/// <summary>
		/// Gets or sets the acting user identity.
		/// </summary>
		public string UserSid { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the event reason.
		/// </summary>
		public string Reason { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the trust scope.
		/// </summary>
		public string Scope { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the trust subject hash.
		/// </summary>
		public string SubjectHash { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the decision identifier when applicable.
		/// </summary>
		public string DecisionId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the SHA256 hash of the previous audit event for chain-integrity validation.
		/// For the first event, this is an empty string.
		/// </summary>
		public string PreviousEventHash { get; set; } = string.Empty;
	}

	/// <summary>
	/// Represents one trust decision.
	/// </summary>
	public sealed class TrustDecisionEntry
	{
		/// <summary>
		/// Gets or sets decision identifier.
		/// </summary>
		public string DecisionId { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets trust scope.
		/// </summary>
		public string Scope { get; set; } = string.Empty;

		/// <summary>
		/// Gets the typed trust scope value.
		/// </summary>
		public TrustDecisionScopeKind ScopeKind
		{
			get
			{
				if (string.Equals(this.Scope, "File", StringComparison.OrdinalIgnoreCase))
				{
					return TrustDecisionScopeKind.File;
				}

				if (string.Equals(this.Scope, "Repository", StringComparison.OrdinalIgnoreCase) ||
					string.Equals(this.Scope, "Repo", StringComparison.OrdinalIgnoreCase))
				{
					return TrustDecisionScopeKind.Repository;
				}

				if (string.Equals(this.Scope, "Baseline", StringComparison.OrdinalIgnoreCase))
				{
					return TrustDecisionScopeKind.Baseline;
				}

				if (string.Equals(this.Scope, "Finding", StringComparison.OrdinalIgnoreCase))
				{
					return TrustDecisionScopeKind.Finding;
				}

				return TrustDecisionScopeKind.Unknown;
			}
		}

		/// <summary>
		/// Gets or sets subject hash or fingerprint.
		/// </summary>
		public string SubjectHash { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets repository remote.
		/// </summary>
		public string RepositoryRemote { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets branch.
		/// </summary>
		public string Branch { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets commit SHA.
		/// </summary>
		public string CommitSha { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets policy profile.
		/// </summary>
		public string PolicyProfile { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets decision action.
		/// </summary>
		public string Decision { get; set; } = string.Empty;

		/// <summary>
		/// Gets the typed trust decision value.
		/// </summary>
		public TrustDecisionKind DecisionKind
		{
			get
			{
				if (string.Equals(this.Decision, "Trust", StringComparison.OrdinalIgnoreCase))
				{
					return TrustDecisionKind.Trust;
				}

				if (string.Equals(this.Decision, "TrustUntilChanged", StringComparison.OrdinalIgnoreCase))
				{
					return TrustDecisionKind.TrustUntilChanged;
				}

				if (string.Equals(this.Decision, "Deny", StringComparison.OrdinalIgnoreCase))
				{
					return TrustDecisionKind.Deny;
				}

				if (string.Equals(this.Decision, "DismissFinding", StringComparison.OrdinalIgnoreCase))
				{
					return TrustDecisionKind.DismissFinding;
				}

				return TrustDecisionKind.Unknown;
			}
		}

		/// <summary>
		/// Gets or sets decision reason.
		/// </summary>
		public string Reason { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets user SID.
		/// </summary>
		public string UserSid { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets creation timestamp.
		/// </summary>
		public DateTimeOffset CreatedAtUtc { get; set; }

		/// <summary>
		/// Gets or sets expiration timestamp.
		/// </summary>
		public DateTimeOffset? ExpiresAtUtc { get; set; }
	}
}
