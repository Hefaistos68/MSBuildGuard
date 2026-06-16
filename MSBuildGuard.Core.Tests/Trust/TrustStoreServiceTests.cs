using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MSBuildGuard.Core.Baseline;
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
		/// Verifies loading a raw JSON trust store fails.
		/// </summary>
		[Test]
		public void Load_ShouldFail_WhenRawJsonIsUnsigned()
		{
			var service = new TrustStoreService();

			var path = Path.Combine(Path.GetTempPath(), $"trust-raw-{Guid.NewGuid():N}.json");

			var rawJson = "{\r\n  \"version\": 1,\r\n  \"decisions\": [\r\n    {\r\n      \"decisionId\": \"5cd109faa53d41158955c652300e9ea9\",\r\n      \"scope\": \"Signer\",\r\n      \"subjectHash\": \"EC240824852A50662166EA955B4BAD3E180440AD\",\r\n      \"decision\": \"Trust\",\r\n      \"reason\": \"Trusted\",\r\n      \"userSid\": \"andreas\"\r\n    }\r\n  ]\r\n}";

			try
			{
				File.WriteAllText(path, rawJson);

				Should.Throw<InvalidDataException>(() => service.Load(path));
			}
			finally
			{
				if (File.Exists(path))
				{
					File.Delete(path);
				}
			}
		}

		/// <summary>
		/// Verifies loading a signed JSON trust store with camelCase properties inside envelope succeeds.
		/// </summary>
		[Test]
		public void Load_ShouldSucceed_WhenSignedEnvelopeHasCamelCaseProperties()
		{
			var service = new TrustStoreService();

			var path = Path.Combine(Path.GetTempPath(), $"trust-raw-{Guid.NewGuid():N}.json");

			var rawJson = "{\r\n  \"version\": 1,\r\n  \"decisions\": [\r\n    {\r\n      \"decisionId\": \"5cd109faa53d41158955c652300e9ea9\",\r\n      \"scope\": \"Signer\",\r\n      \"subjectHash\": \"EC240824852A50662166EA955B4BAD3E180440AD\",\r\n      \"decision\": \"Trust\",\r\n      \"reason\": \"Trusted\",\r\n      \"userSid\": \"andreas\"\r\n    }\r\n  ]\r\n}";

			var originalAllowSharing = CoreSettings.AllowSharingTrustsInRepositories;

			try
			{
				CoreSettings.AllowSharingTrustsInRepositories = true;

				var signatureService = new MSBuildGuard.Core.Baseline.JsonSignatureService();

				var signedPayload = signatureService.CreateSignedEnvelopeJson(rawJson, "MSBuildGuard.TrustStore.v1");

				File.WriteAllText(path, signedPayload);

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
				CoreSettings.AllowSharingTrustsInRepositories = originalAllowSharing;

				if (File.Exists(path))
				{
					File.Delete(path);
				}
			}
		}

		/// <summary>
		/// Verifies that package directory hash calculation is deterministic.
		/// </summary>
		[Test]
		public void CalculatePackageDirectoryHash_ShouldBeDeterministic()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"pkg-deterministic-{Guid.NewGuid():N}");

			try
			{
				Directory.CreateDirectory(path);

				var file1 = Path.Combine(path, "a.props");
				var file2 = Path.Combine(path, "build", "b.targets");

				Directory.CreateDirectory(Path.Combine(path, "build"));

				File.WriteAllText(file1, "content-a");
				File.WriteAllText(file2, "content-b");

				var hash1 = TrustStoreService.CalculatePackageDirectoryHash(path);
				var hash2 = TrustStoreService.CalculatePackageDirectoryHash(path);

				hash1.ShouldNotBeEmpty();
				hash1.ShouldBe(hash2);
			}
			finally
			{
				if (Directory.Exists(path))
				{
					Directory.Delete(path, true);
				}
			}
		}

		/// <summary>
		/// Verifies that modifying a file in a package directory alters the calculated hash.
		/// </summary>
		[Test]
		public void CalculatePackageDirectoryHash_ShouldChange_WhenFileIsModified()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"pkg-modify-{Guid.NewGuid():N}");

			try
			{
				Directory.CreateDirectory(path);

				var file1 = Path.Combine(path, "a.props");

				File.WriteAllText(file1, "content-a");

				var originalHash = TrustStoreService.CalculatePackageDirectoryHash(path);

				File.WriteAllText(file1, "content-modified");

				var modifiedHash = TrustStoreService.CalculatePackageDirectoryHash(path);

				originalHash.ShouldNotBe(modifiedHash);
			}
			finally
			{
				if (Directory.Exists(path))
				{
					Directory.Delete(path, true);
				}
			}
		}

		/// <summary>
		/// Verifies that package trust decisions approve or reject matching NuGet packages.
		/// </summary>
		[Test]
		public void IsFindingApprovedByPackage_ShouldApproveOrRejectMatchingPackages()
		{
			var service = new TrustStoreService();
			var store = new TrustStoreDocument();
			var packageId = "NUnit";
			var packageVersion = "4.6.0";
			var userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
			var packageDir = Path.Combine(userHome, ".nuget", "packages", packageId.ToLowerInvariant(), packageVersion.ToLowerInvariant());

			if (!Directory.Exists(packageDir))
			{
				Assert.Ignore("NUnit package directory not found in global cache.");
			}

			var expectedHash = TrustStoreService.CalculatePackageDirectoryHash(packageDir);

			store.Decisions.Add(new TrustDecisionEntry
			{
				DecisionId     = Guid.NewGuid().ToString("N"),
				Scope          = "Package",
				SubjectHash    = expectedHash,
				AssemblySigner = $"{packageId}@{packageVersion}".ToLowerInvariant(),
				Decision       = "Trust",
				CreatedAtUtc   = DateTimeOffset.UtcNow
			});

			service.IsFindingApprovedByPackage(store, packageId, packageVersion).ShouldBeTrue();

			var otherStore = new TrustStoreDocument();

			otherStore.Decisions.Add(new TrustDecisionEntry
			{
				DecisionId     = Guid.NewGuid().ToString("N"),
				Scope          = "Package",
				SubjectHash    = "wrong-hash",
				AssemblySigner = $"{packageId}@{packageVersion}".ToLowerInvariant(),
				Decision       = "Trust",
				CreatedAtUtc   = DateTimeOffset.UtcNow
			});

			service.IsFindingApprovedByPackage(otherStore, packageId, packageVersion).ShouldBeFalse();
		}

		/// <summary>
		/// Verifies that Load throws an InvalidDataException when EnforceAsymmetricSignatures is true and the signature stream is missing.
		/// </summary>
		[Test]
		public void Load_ShouldThrowInvalidDataException_WhenEnforceAsymmetricSignaturesIsTrueAndSignatureIsMissing()
		{
			var service = new TrustStoreService();
			var rootPath = Path.Combine(Path.GetTempPath(), $"trust-test-{Guid.NewGuid():N}");
			var slnDir = Path.Combine(rootPath, "repo", ".msbuildguard");
			var path = Path.Combine(slnDir, "trust.json");

			var originalEnforce = CoreSettings.EnforceAsymmetricSignatures;
			var originalAllowSharing = CoreSettings.AllowSharingTrustsInRepositories;

			try
			{
				CoreSettings.EnforceAsymmetricSignatures = false;
				CoreSettings.AllowSharingTrustsInRepositories = true;

				service.Save(path, new TrustStoreDocument());

				CoreSettings.EnforceAsymmetricSignatures = true;

				Should.Throw<InvalidDataException>(() => service.Load(path))
					.Message.ShouldContain("Asymmetric signature is required but missing");
			}
			finally
			{
				CoreSettings.EnforceAsymmetricSignatures = originalEnforce;
				CoreSettings.AllowSharingTrustsInRepositories = originalAllowSharing;

				if (Directory.Exists(rootPath))
				{
					Directory.Delete(rootPath, true);
				}
			}
		}

		/// <summary>
		/// Verifies that loading a trust store file which has an asymmetric signature triggers repository pinning,
		/// and subsequent loads of an unsigned trust store in the same directory fail even if global enforcement is false.
		/// </summary>
		[Test]
		public void Load_ShouldEnforceAsymmetricSignature_WhenRepositoryIsPinned()
		{
			var service = new TrustStoreService();
			var rootPath = Path.Combine(Path.GetTempPath(), $"trust-pin-{Guid.NewGuid():N}");
			var slnDir = Path.Combine(rootPath, "repo", ".msbuildguard");
			var path = Path.Combine(slnDir, "trust.json");

			using var certificate = CreateSelfSignedCertificate();

			AddCertificate(StoreName.My, StoreLocation.CurrentUser, certificate);
			AddCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate);
			Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", "true");

			var originalAllowSharing = CoreSettings.AllowSharingTrustsInRepositories;
			var originalEnforce = CoreSettings.EnforceAsymmetricSignatures;

			try
			{
				CoreSettings.AllowSharingTrustsInRepositories = true;
				CoreSettings.EnforceAsymmetricSignatures = false;

				service.Save(path, new TrustStoreDocument());
				service.Sign(path, certificate.Thumbprint);

				// Loading the signed file should succeed and trigger pinning
				var loaded = service.Load(path);

				loaded.ShouldNotBeNull();

				// Delete the signature stream to simulate an unsigned file update
				var sigPath = path + ".signature";

				if (File.Exists(sigPath))
				{
					File.Delete(sigPath);
				}

				// Trying to load the now-unsigned file in the pinned repository should throw
				Should.Throw<InvalidDataException>(() => service.Load(path))
					.Message.ShouldContain("Asymmetric signature is required for this pinned repository");
			}
			finally
			{
				CoreSettings.AllowSharingTrustsInRepositories = originalAllowSharing;
				CoreSettings.EnforceAsymmetricSignatures = originalEnforce;
				Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", null);
				RemoveCertificate(StoreName.My, StoreLocation.CurrentUser, certificate.Thumbprint);
				RemoveCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate.Thumbprint);

				if (Directory.Exists(rootPath))
				{
					Directory.Delete(rootPath, true);
				}
			}
		}

		/// <summary>
		/// Verifies that saving a trust store that already has an asymmetric signature automatically updates/re-signs the signature companion file.
		/// </summary>
		[Test]
		public void Save_ShouldAutomaticallyUpdateSignature_WhenAlreadyAsymmetricSigned()
		{
			var service = new TrustStoreService();
			var rootPath = Path.Combine(Path.GetTempPath(), $"trust-auto-resign-{Guid.NewGuid():N}");
			var slnDir = Path.Combine(rootPath, "repo", ".msbuildguard");
			var path = Path.Combine(slnDir, "trust.json");

			using var certificate = CreateSelfSignedCertificate();

			AddCertificate(StoreName.My, StoreLocation.CurrentUser, certificate);
			AddCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate);
			Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", "true");

			var originalAllowSharing = CoreSettings.AllowSharingTrustsInRepositories;
			var originalEnforce = CoreSettings.EnforceAsymmetricSignatures;

			try
			{
				CoreSettings.AllowSharingTrustsInRepositories = true;
				CoreSettings.EnforceAsymmetricSignatures = false;

				var store = new TrustStoreDocument();

				service.Save(path, store);
				service.Sign(path, certificate.Thumbprint);

				// Modify document and save again
				var loaded = service.Load(path);

				loaded.Decisions.Add(new TrustDecisionEntry
				{
					DecisionId = Guid.NewGuid().ToString("N"),
					Scope = "Finding",
					SubjectHash = "fp-auto-resign",
					Decision = "TrustUntilChanged",
					CreatedAtUtc = DateTimeOffset.UtcNow
				});

				// Save should automatically re-sign using the existing thumbprint
				service.Save(path, loaded);

				// Subsequent load should succeed (validating the new asymmetric signature)
				var reloaded = service.Load(path);

				reloaded.ShouldNotBeNull();
				service.IsFingerprintApproved(reloaded, "fp-auto-resign").ShouldBeTrue();
			}
			finally
			{
				CoreSettings.AllowSharingTrustsInRepositories = originalAllowSharing;
				CoreSettings.EnforceAsymmetricSignatures = originalEnforce;
				Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", null);
				RemoveCertificate(StoreName.My, StoreLocation.CurrentUser, certificate.Thumbprint);
				RemoveCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate.Thumbprint);

				if (Directory.Exists(rootPath))
				{
					Directory.Delete(rootPath, true);
				}
			}
		}

		/// <summary>
		/// Verifies that saving a trust store when EnforceAsymmetricSignatures is true automatically signs the trust store file.
		/// </summary>
		[Test]
		public void Save_ShouldAutomaticallySign_WhenEnforceAsymmetricSignaturesIsTrue()
		{
			var service = new TrustStoreService();
			var rootPath = Path.Combine(Path.GetTempPath(), $"trust-auto-sign-{Guid.NewGuid():N}");
			var slnDir = Path.Combine(rootPath, "repo", ".msbuildguard");
			var path = Path.Combine(slnDir, "trust.json");

			using var certificate = CreateSelfSignedCertificate();

			AddCertificate(StoreName.My, StoreLocation.CurrentUser, certificate);
			AddCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate);
			Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", "true");
			Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_SIGNING_CERT_THUMBPRINT", certificate.Thumbprint);

			var originalAllowSharing = CoreSettings.AllowSharingTrustsInRepositories;
			var originalEnforce = CoreSettings.EnforceAsymmetricSignatures;

			try
			{
				CoreSettings.AllowSharingTrustsInRepositories = true;
				CoreSettings.EnforceAsymmetricSignatures = true;

				var store = new TrustStoreDocument();

				// Save should automatically sign because enforcement is enabled
				service.Save(path, store);

				// Subsequent load should succeed
				var loaded = service.Load(path);

				loaded.ShouldNotBeNull();
			}
			finally
			{
				CoreSettings.AllowSharingTrustsInRepositories = originalAllowSharing;
				CoreSettings.EnforceAsymmetricSignatures = originalEnforce;
				Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", null);
				Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_SIGNING_CERT_THUMBPRINT", null);
				RemoveCertificate(StoreName.My, StoreLocation.CurrentUser, certificate.Thumbprint);
				RemoveCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate.Thumbprint);

				if (Directory.Exists(rootPath))
				{
					Directory.Delete(rootPath, true);
				}
			}
		}

		/// <summary>
		/// Verifies that user trust store saves use a unique local DPAPI key (or fallback unprotected key) rather than the static shared key.
		/// </summary>
		[Test]
		public void GetSigningKey_ShouldBeUniquePerUserMachine()
		{
			var service = new TrustStoreService();
			var tempPath = Path.Combine(Path.GetTempPath(), $"user-trust-{Guid.NewGuid():N}.json");
			var originalAllowSharing = CoreSettings.AllowSharingTrustsInRepositories;

			try
			{
				CoreSettings.AllowSharingTrustsInRepositories = false;

				var store = new TrustStoreDocument();

				service.Save(tempPath, store);

				// If we load it, it should succeed because it uses the local key
				var loaded = service.Load(tempPath);

				loaded.ShouldNotBeNull();

				// If we try to verify the signature of the file using the static TrustStoreSigningKey, it should fail
				var payload = File.ReadAllText(tempPath);
				var signatureService = new JsonSignatureService();
				string? trustPayload;
				var verifiedWithStaticKey = signatureService.TryVerifyAndExtract<string>(payload, "MSBuildGuard.TrustStore.v1", out trustPayload);

				verifiedWithStaticKey.ShouldBeFalse();
			}
			finally
			{
				CoreSettings.AllowSharingTrustsInRepositories = originalAllowSharing;

				if (File.Exists(tempPath))
				{
					File.Delete(tempPath);
				}
			}
		}

		/// <summary>
		/// Verifies that loading a trust store fails when the audit log file has been modified (chain link broken).
		/// </summary>
		[Test]
		public void Load_ShouldThrowInvalidDataException_WhenAuditTrailIsTampered()
		{
			var service = new TrustStoreService();
			var path = Path.Combine(Path.GetTempPath(), $"trust-tamper-{Guid.NewGuid():N}.json");

			try
			{
				service.AddDecision(path, new TrustDecisionEntry
				{
					CreatedAtUtc = DateTimeOffset.UtcNow,
					Decision = "TrustUntilChanged",
					DecisionId = Guid.NewGuid().ToString("N"),
					Reason = "approval",
					Scope = "Finding",
					SubjectHash = "fp-1",
					UserSid = "tester"
				});

				service.AddDecision(path, new TrustDecisionEntry
				{
					CreatedAtUtc = DateTimeOffset.UtcNow,
					Decision = "TrustUntilChanged",
					DecisionId = Guid.NewGuid().ToString("N"),
					Reason = "approval",
					Scope = "Finding",
					SubjectHash = "fp-2",
					UserSid = "tester"
				});

				var auditPath = service.GetAuditPathForStore(path);
				var lines = File.ReadAllLines(auditPath);

				// Modify a line in the middle to break the hash chain
				if (lines.Length >= 2)
				{
					lines[0] = lines[0].Replace("fp-1", "fp-1-tampered");
					File.WriteAllLines(auditPath, lines);
				}

				Should.Throw<InvalidDataException>(() => service.Load(path));
			}
			finally
			{
				if (File.Exists(path))
				{
					File.Delete(path);
				}

				var auditPath = service.GetAuditPathForStore(path);

				if (File.Exists(auditPath))
				{
					File.Delete(auditPath);
				}
			}
		}

		private static X509Certificate2 CreateSelfSignedCertificate()
		{
			using var rsa = RSA.Create(2048);
			var request = new CertificateRequest(
				$"CN=MSBuildGuard-TrustTests-{Guid.NewGuid():N}",
				rsa,
				HashAlgorithmName.SHA256,
				RSASignaturePadding.Pkcs1);

			request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
			request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

			var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(7));
			var pfx = certificate.Export(X509ContentType.Pfx);

			return X509CertificateLoader.LoadPkcs12(pfx, string.Empty, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
		}

		private static void AddCertificate(StoreName storeName, StoreLocation storeLocation, X509Certificate2 certificate)
		{
			using var store = new X509Store(storeName, storeLocation);

			store.Open(OpenFlags.ReadWrite);
			store.Add(certificate);
		}

		private static void RemoveCertificate(StoreName storeName, StoreLocation storeLocation, string thumbprint)
		{
			using var store = new X509Store(storeName, storeLocation);

			store.Open(OpenFlags.ReadWrite);
			var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

			foreach (var certificate in certificates)
			{
				store.Remove(certificate);
			}
		}
	}
}
