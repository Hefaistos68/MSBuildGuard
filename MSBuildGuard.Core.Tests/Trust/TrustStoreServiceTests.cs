using System;
using System.IO;
using System.Linq;
using MSBuildGuard.Core.Trust;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Tests.Trust
{
	/// <summary>
	/// Tests for <see cref="TrustStoreService"/>.
	/// </summary>
	[TestFixture]
	public sealed class TrustStoreServiceTests
	{
		/// <summary>
		/// Verifies trust decision persistence and fingerprint approval lookup.
		/// </summary>
		[Test]
		public void TrustStoreService_ShouldPersistAndResolveFingerprintApproval()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid():N}.json");
			var decision = new TrustDecisionEntry
			{
				DecisionId = Guid.NewGuid().ToString("N"),
				Scope = "Finding",
				SubjectHash = "fp-100",
				Decision = "TrustUntilChanged",
				CreatedAtUtc = DateTimeOffset.UtcNow
			};

			service.AddDecision(path, decision);

			var loaded = service.Load(path);

			service.IsFingerprintApproved(loaded, "fp-100").ShouldBeTrue();

			var rawPayload = File.ReadAllText(path);

			rawPayload.ShouldContain("SignatureV1");
			rawPayload.ShouldContain("\"JSON\"");
			rawPayload.ShouldContain("fp-100");
		}

		/// <summary>
		/// Verifies loading fails for malformed signed envelope payload.
		/// </summary>
		[Test]
		public void Load_ShouldThrowInvalidDataException_WhenSignedPayloadIsInvalid()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid():N}.json");

			File.WriteAllText(path, "{\"SignatureV1\":\"invalid\",\"JSON\":\"tampered\"}");

			Should.Throw<InvalidDataException>(() => service.Load(path));
		}

		/// <summary>
		/// Verifies loading fails when the signed payload has been tampered with.
		/// </summary>
		[Test]
		public void Load_ShouldThrowInvalidDataException_WhenSignedPayloadIsTampered()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid():N}.json");
			var store = new TrustStoreDocument();

			store.Decisions.Add(new TrustDecisionEntry
			{
				CreatedAtUtc = DateTimeOffset.UtcNow,
				Decision = "TrustUntilChanged",
				DecisionId = Guid.NewGuid().ToString("N"),
				Scope = "Finding",
				SubjectHash = "fp-tamper"
			});

			service.Save(path, store);

			var payload = File.ReadAllText(path).Replace("fp-tamper", "fp-tampered");

			File.WriteAllText(path, payload);

			Should.Throw<InvalidDataException>(() => service.Load(path));
		}

		/// <summary>
		/// Verifies expired finding trust decisions no longer approve a fingerprint.
		/// </summary>
		[Test]
		public void IsFingerprintApproved_ShouldReturnFalse_WhenDecisionIsExpired()
		{
			var service = new TrustStoreService();
			var store = new TrustStoreDocument();

			store.Decisions.Add(new TrustDecisionEntry
			{
				CreatedAtUtc  = DateTimeOffset.UtcNow.AddDays(-2),
				Decision      = "TrustUntilChanged",
				DecisionId    = Guid.NewGuid().ToString("N"),
				ExpiresAtUtc  = DateTimeOffset.UtcNow.AddDays(-1),
				Scope         = "Finding",
				SubjectHash   = "fp-expired"
			});

			service.IsFingerprintApproved(store, "fp-expired").ShouldBeFalse();
		}

		/// <summary>
		/// Verifies repository trust requires matching remote and commit.
		/// </summary>
		[Test]
		public void IsRepositoryTrusted_ShouldMatchRemoteAndCommit()
		{
			var service = new TrustStoreService();
			var store = new TrustStoreDocument();

			store.Decisions.Add(new TrustDecisionEntry
			{
				Branch           = "main",
				CommitSha        = "abc123",
				CreatedAtUtc     = DateTimeOffset.UtcNow,
				Decision         = "Trust",
				DecisionId       = Guid.NewGuid().ToString("N"),
				PolicyProfile    = "default",
				RepositoryRemote = "origin",
				Scope            = "Repository"
			});

			service.IsRepositoryTrusted(store, "origin", "main", "abc123", "default").ShouldBeTrue();
			service.IsRepositoryTrusted(store, "origin", "release", "abc123", "default").ShouldBeFalse();
			service.IsRepositoryTrusted(store, "origin", "main", "def456", "default").ShouldBeFalse();
		}

		/// <summary>
		/// Verifies file-scope trust can approve findings for the matching file hash and context.
		/// </summary>
		[Test]
		public void IsFindingApproved_ShouldHonorFileScopeTrust_WhenContextMatches()
		{
			var service = new TrustStoreService();
			var store = new TrustStoreDocument();
			var trustContext = new ScanTrustContext
			{
				Branch           = "main",
				CommitSha        = "abc123",
				RepositoryRemote = "origin"
			};

			store.Decisions.Add(new TrustDecisionEntry
			{
				Branch           = "main",
				CommitSha        = "abc123",
				CreatedAtUtc     = DateTimeOffset.UtcNow,
				Decision         = "TrustUntilChanged",
				DecisionId       = Guid.NewGuid().ToString("N"),
				PolicyProfile    = "default",
				RepositoryRemote = "origin",
				Scope            = "File",
				SubjectHash      = "file-hash-1"
			});

			service.IsFindingApproved(store, "fp-200", "file-hash-1", trustContext, "default").ShouldBeTrue();
			service.IsFindingApproved(store, "fp-200", "file-hash-1", new ScanTrustContext { RepositoryRemote = "fork" }, "default").ShouldBeFalse();
		}

		/// <summary>
		/// Verifies finding-scope trust respects policy profile matching.
		/// </summary>
		[Test]
		public void IsFindingApproved_ShouldRequireMatchingPolicyProfile_WhenEntrySpecifiesOne()
		{
			var service = new TrustStoreService();
			var store = new TrustStoreDocument();
			var trustContext = new ScanTrustContext();

			store.Decisions.Add(new TrustDecisionEntry
			{
				CreatedAtUtc  = DateTimeOffset.UtcNow,
				Decision      = "TrustUntilChanged",
				DecisionId    = Guid.NewGuid().ToString("N"),
				PolicyProfile = "default",
				Scope         = "Finding",
				SubjectHash   = "fp-500"
			});

			service.IsFindingApproved(store, "fp-500", "file-hash-2", trustContext, "default").ShouldBeTrue();
			service.IsFindingApproved(store, "fp-500", "file-hash-2", trustContext, "hooks").ShouldBeFalse();
		}

		/// <summary>
		/// Verifies adding a trust decision appends an audit log event.
		/// </summary>
		[Test]
		public void AddDecision_ShouldAppendAuditEvent()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid():N}.json");

			service.AddDecision(path, new TrustDecisionEntry
			{
				CreatedAtUtc = DateTimeOffset.UtcNow,
				Decision = "TrustUntilChanged",
				DecisionId = Guid.NewGuid().ToString("N"),
				Reason = "approval",
				Scope = "Finding",
				SubjectHash = "fp-audit",
				UserSid = "tester"
			});

			var auditPath = service.GetAuditPathForStore(path);
			var events = service.ReadAudit(auditPath);

			events.Count.ShouldBe(1);
			events[0].EventKind.ShouldBe("AddDecision");
			events[0].SubjectHash.ShouldBe("fp-audit");
		}

		/// <summary>
		/// Verifies revoking by subject removes matching entries and appends revoke audit events.
		/// </summary>
		[Test]
		public void RemoveDecisionsBySubject_ShouldRemoveMatchesAndAppendAuditEvents()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid():N}.json");

			service.AddDecision(path, new TrustDecisionEntry
			{
				CreatedAtUtc = DateTimeOffset.UtcNow,
				Decision = "TrustUntilChanged",
				DecisionId = Guid.NewGuid().ToString("N"),
				Reason = "approval",
				Scope = "Finding",
				SubjectHash = "fp-remove",
				UserSid = "tester"
			});

			service.AddDecision(path, new TrustDecisionEntry
			{
				CreatedAtUtc = DateTimeOffset.UtcNow,
				Decision = "TrustUntilChanged",
				DecisionId = Guid.NewGuid().ToString("N"),
				Reason = "approval",
				Scope = "File",
				SubjectHash = "file-hash-keep",
				UserSid = "tester"
			});

			var removed = service.RemoveDecisionsBySubject(path, "fp-remove", "revoke", "tester");

			removed.ShouldBe(1);

			var store = service.Load(path);

			store.Decisions.Count.ShouldBe(1);
			store.Decisions[0].SubjectHash.ShouldBe("file-hash-keep");

			var auditPath = service.GetAuditPathForStore(path);
			var events = service.ReadAudit(auditPath);

			events.Any(item => item.EventKind == "RevokeDecision" && item.SubjectHash == "fp-remove").ShouldBeTrue();
		}

		/// <summary>
		/// Verifies resetting the store writes an empty trust store and logs the reset event.
		/// </summary>
		[Test]
		public void ResetStore_ShouldClearDecisionsAndAppendResetAuditEvent()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"trust-{Guid.NewGuid():N}.json");

			service.AddDecision(path, new TrustDecisionEntry
			{
				CreatedAtUtc = DateTimeOffset.UtcNow,
				Decision = "TrustUntilChanged",
				DecisionId = Guid.NewGuid().ToString("N"),
				Reason = "approval",
				Scope = "Finding",
				SubjectHash = "fp-reset",
				UserSid = "tester"
			});

			service.ResetStore(path, "recover", "tester");

			var store = service.Load(path);

			store.Decisions.Count.ShouldBe(0);

			var auditPath = service.GetAuditPathForStore(path);
			var events = service.ReadAudit(auditPath);

			events.Any(item => item.EventKind == "ResetStore").ShouldBeTrue();
		}

		/// <summary>
		/// Verifies solution-scoped trust store path resolution.
		/// </summary>
		[Test]
		public void GetSolutionTrustPath_ShouldReturnDotMsBuildGuardPathUnderSolutionDirectory()
		{
			var service = new TrustStoreService();
			var solutionPath = Path.Combine(Path.GetTempPath(), "repo", "Sample.slnx");

			var resolvedPath = service.GetSolutionTrustPath(solutionPath);

			resolvedPath.ShouldBe(Path.Combine(Path.GetDirectoryName(solutionPath)!, ".msbuildguard", "trust.json"));
		}

		/// <summary>
		/// Verifies project-scoped trust store path resolution.
		/// </summary>
		[Test]
		public void GetProjectTrustPath_ShouldReturnDotMsBuildGuardPathUnderProjectDirectory()
		{
			var service = new TrustStoreService();
			var projectPath = Path.Combine(Path.GetTempPath(), "repo", "src", "App", "App.csproj");

			var resolvedPath = service.GetProjectTrustPath(projectPath);

			resolvedPath.ShouldBe(Path.Combine(Path.GetDirectoryName(projectPath)!, ".msbuildguard", "trust.json"));
		}

		/// <summary>
		/// Verifies merged trust store includes decisions from user, solution, and project scopes.
		/// </summary>
		[Test]
		public void LoadMergedTrustStore_ShouldAggregateDecisionsAcrossAllScopes()
		{
			var service = new TrustStoreService();
			var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-merged-{Guid.NewGuid():N}");
			var solutionDirectory = Path.Combine(rootPath, "repo");
			var projectDirectory = Path.Combine(solutionDirectory, "src", "App");
			var solutionPath = Path.Combine(solutionDirectory, "App.slnx");
			var projectPath = Path.Combine(projectDirectory, "App.csproj");
			var userPath = Path.Combine(rootPath, "user", "trust.json");
			var solutionTrustPath = service.GetSolutionTrustPath(solutionPath);
			var projectTrustPath = service.GetProjectTrustPath(projectPath);

			service.Save(userPath, new TrustStoreDocument
			{
				Decisions = new[]
				{
					new TrustDecisionEntry
					{
						CreatedAtUtc = DateTimeOffset.UtcNow,
						Decision = "Trust",
						DecisionId = Guid.NewGuid().ToString("N"),
						Scope = "Finding",
						SubjectHash = "user-decision"
					}
				}
			});

			service.Save(solutionTrustPath, new TrustStoreDocument
			{
				Decisions = new[]
				{
					new TrustDecisionEntry
					{
						CreatedAtUtc = DateTimeOffset.UtcNow,
						Decision = "Trust",
						DecisionId = Guid.NewGuid().ToString("N"),
						Scope = "Assembly",
						SubjectHash = "solution-decision"
					}
				}
			});

			service.Save(projectTrustPath, new TrustStoreDocument
			{
				Decisions = new[]
				{
					new TrustDecisionEntry
					{
						CreatedAtUtc = DateTimeOffset.UtcNow,
						Decision = "Trust",
						DecisionId = Guid.NewGuid().ToString("N"),
						Scope = "Signer",
						SubjectHash = "project-decision"
					}
				}
			});

			var merged = service.LoadMergedTrustStore(userPath, solutionPath, projectPath);

			merged.Decisions.Count.ShouldBe(3);
			merged.Decisions.Any(item => item.SubjectHash == "user-decision").ShouldBeTrue();
			merged.Decisions.Any(item => item.SubjectHash == "solution-decision").ShouldBeTrue();
			merged.Decisions.Any(item => item.SubjectHash == "project-decision").ShouldBeTrue();
		}

		/// <summary>
		/// Verifies loading a raw JSON trust store with camelCase properties succeeds.
		/// </summary>
		[Test]
		public void Load_ShouldSucceed_WhenRawJsonHasCamelCaseProperties()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"trust-raw-{Guid.NewGuid():N}.json");
			var rawJson = "{\r\n  \"version\": 1,\r\n  \"decisions\": [\r\n    {\r\n      \"decisionId\": \"5cd109faa53d41158955c652300e9ea9\",\r\n      \"scope\": \"Signer\",\r\n      \"subjectHash\": \"EC240824852A50662166EA955B4BAD3E180440AD\",\r\n      \"decision\": \"Trust\",\r\n      \"reason\": \"Trusted\",\r\n      \"userSid\": \"andreas\"\r\n    }\r\n  ]\r\n}";

			try
			{
				File.WriteAllText(path, rawJson);

				var store = service.Load(path);

				store.ShouldNotBeNull();
				store.Version.ShouldBe(1);
				store.Decisions.Count.ShouldBe(1);
				store.Decisions[0].DecisionId.ShouldBe("5cd109faa53d41158955c652300e9ea9");
				store.Decisions[0].Scope.ShouldBe("Signer");
				store.Decisions[0].SubjectHash.ShouldBe("EC240824852A50662166EA955B4BAD3E180440AD");
				store.Decisions[0].Decision.ShouldBe("Trust");
			}
			finally
			{
				if (File.Exists(path))
				{
					File.Delete(path);
				}
			}
		}
	}
}
