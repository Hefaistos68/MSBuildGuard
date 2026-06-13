using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using MSBuildGuard.Core.Baseline;

namespace MSBuildGuard.Core.Trust
{
	/// <summary>
	/// Provides trust store persistence and lookup operations.
	/// </summary>
	public sealed class TrustStoreService
	{
		private const string TrustStoreSigningKey = "MSBuildGuard.TrustStore.v1";

		private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
		{
			WriteIndented               = true,
			PropertyNameCaseInsensitive = true,
			Converters                  = { new JsonStringEnumConverter() }
		};

		private static readonly JsonSerializerOptions AuditSerializerOptions = new JsonSerializerOptions
		{
			WriteIndented = false
		};

		/// <summary>
		/// Loads trust store content from disk.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <returns>The loaded trust document.</returns>
		public TrustStoreDocument Load(string path)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			if (!File.Exists(path))
			{
				return new TrustStoreDocument();
			}

			var payload = File.ReadAllText(path);
			var signatureService = new JsonSignatureService();

			var isEnvelopeFormat = false;

			try
			{
				using var doc = JsonDocument.Parse(payload);
				isEnvelopeFormat = doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("SignatureV1", out _);
			}
			catch (JsonException)
			{
			}

			string? trustPayload;
			var isEnvelopeSigned = signatureService.TryVerifyAndExtract<string>(payload, TrustStoreSigningKey, out trustPayload) && !string.IsNullOrWhiteSpace(trustPayload);

			if (isEnvelopeFormat)
			{
				if (!isEnvelopeSigned)
				{
					throw new InvalidDataException("Trust store signature validation failed. Do not modify the contents of this file manually.");
				}
			}
			else
			{
				try
				{
					var directTrust = JsonSerializer.Deserialize<TrustStoreDocument>(payload, SerializerOptions);

					if (directTrust != null)
					{
						return directTrust;
					}
				}
				catch
				{
				}

				throw new InvalidDataException("Trust store signature validation failed. Do not modify the contents of this file manually.");
			}

			var trust = JsonSerializer.Deserialize<TrustStoreDocument>(trustPayload!, SerializerOptions);

			if (trust == null)
			{
				throw new InvalidDataException("Unable to deserialize decrypted trust store content.");
			}

			return trust;
		}

		/// <summary>
		/// Saves trust store content to disk.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <param name="document">The trust document.</param>
		public void Save(string path, TrustStoreDocument document)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			if (document == null)
			{
				throw new ArgumentNullException(nameof(document));
			}

			var directory = Path.GetDirectoryName(path);

			if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
			{
				Directory.CreateDirectory(directory);
			}

			var trustPayload = JsonSerializer.Serialize(document, SerializerOptions);
			var payload = new JsonSignatureService().CreateSignedEnvelopeJson(trustPayload, TrustStoreSigningKey);

			WriteAllTextAtomic(path, payload);
		}

		/// <summary>
		/// Writes text content to disk atomically by using a temporary file in the destination directory.
		/// </summary>
		/// <param name="path">Destination file path.</param>
		/// <param name="content">File content to write.</param>
		private static void WriteAllTextAtomic(string path, string content)
		{
			var directory = Path.GetDirectoryName(path);

			if (string.IsNullOrWhiteSpace(directory))
			{
				throw new InvalidOperationException("Trust store path must include a directory.");
			}

			var tempPath = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");

			File.WriteAllText(tempPath, content);

			try
			{
				if (File.Exists(path))
				{
					File.Replace(tempPath, path, null, true);

					return;
				}

				File.Move(tempPath, path);
			}
			finally
			{
				if (File.Exists(tempPath))
				{
					File.Delete(tempPath);
				}
			}
		}

		/// <summary>
		/// Adds a trust decision entry and persists the updated store.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <param name="entry">Decision entry to add.</param>
		public void AddDecision(string path, TrustDecisionEntry entry)
		{
			if (entry == null)
			{
				throw new ArgumentNullException(nameof(entry));
			}

			var store = Load(path);
			store.Decisions.Add(entry);
			Save(path, store);
			AppendAuditEvent(path, CreateAuditEvent("AddDecision", entry, entry.Reason, entry.UserSid));
		}

		/// <summary>
		/// Removes trust decisions that match the provided subject hash.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <param name="subjectHash">Subject hash to revoke.</param>
		/// <param name="reason">Revocation reason.</param>
		/// <param name="userSid">Acting user identity.</param>
		/// <returns>The number of removed decisions.</returns>
		public int RemoveDecisionsBySubject(string path, string subjectHash, string reason, string userSid)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			if (subjectHash == null)
			{
				throw new ArgumentNullException(nameof(subjectHash));
			}

			if (reason == null)
			{
				throw new ArgumentNullException(nameof(reason));
			}

			if (userSid == null)
			{
				throw new ArgumentNullException(nameof(userSid));
			}

			var store = Load(path);
			var matches = store.Decisions.Where(entry => string.Equals(entry.SubjectHash, subjectHash, StringComparison.OrdinalIgnoreCase)).ToList();

			if (matches.Count == 0)
			{
				return 0;
			}

			foreach (var match in matches)
			{
				store.Decisions.Remove(match);
			}

			Save(path, store);

			foreach (var match in matches)
			{
				AppendAuditEvent(path, CreateAuditEvent("RevokeDecision", match, reason, userSid));
			}

			return matches.Count;
		}

		/// <summary>
		/// Resets the trust store to an empty document and records a recovery event.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <param name="reason">Reset reason.</param>
		/// <param name="userSid">Acting user identity.</param>
		public void ResetStore(string path, string reason, string userSid)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			if (reason == null)
			{
				throw new ArgumentNullException(nameof(reason));
			}

			if (userSid == null)
			{
				throw new ArgumentNullException(nameof(userSid));
			}

			Save(path, new TrustStoreDocument());

			AppendAuditEvent(path, new TrustAuditEvent
			{
				DecisionId = string.Empty,
				EventId = Guid.NewGuid().ToString("N"),
				EventKind = "ResetStore",
				OccurredAtUtc = DateTimeOffset.UtcNow,
				Reason = reason,
				Scope = string.Empty,
				SubjectHash = string.Empty,
				UserSid = userSid
			});
		}

		/// <summary>
		/// Reads append-only trust audit events from disk and validates chain integrity.
		/// </summary>
		/// <param name="auditPath">Audit log path.</param>
		/// <returns>The audit events found in the log.</returns>
		/// <exception cref="InvalidOperationException">Thrown when audit trail integrity is compromised.</exception>
		public IList<TrustAuditEvent> ReadAudit(string auditPath)
		{
			if (auditPath == null)
			{
				throw new ArgumentNullException(nameof(auditPath));
			}

			var events = new List<TrustAuditEvent>();

			if (!File.Exists(auditPath))
			{
				return events;
			}

			foreach (var line in File.ReadLines(auditPath))
			{
				if (string.IsNullOrWhiteSpace(line))
				{
					continue;
				}

				var auditEvent = JsonSerializer.Deserialize<TrustAuditEvent>(line, AuditSerializerOptions);

				if (auditEvent == null)
				{
					continue;
				}

				events.Add(auditEvent);
			}

			ValidateAuditChainIntegrity(events);

			return events;
		}

		/// <summary>
		/// Determines whether an assembly (by name and version) is approved in trust store.
		/// </summary>
		/// <param name="store">Trust store document.</param>
		/// <param name="assemblyName">Assembly name (e.g., package ID).</param>
		/// <param name="assemblyVersion">Assembly version.</param>
		/// <returns><see langword="true"/> when approved; otherwise <see langword="false"/>.</returns>
		public bool IsAssemblyApproved(TrustStoreDocument store, string assemblyName, string assemblyVersion)
		{
			if (store == null)
			{
				throw new ArgumentNullException(nameof(store));
			}

			if (assemblyName == null)
			{
				throw new ArgumentNullException(nameof(assemblyName));
			}

			if (assemblyVersion == null)
			{
				throw new ArgumentNullException(nameof(assemblyVersion));
			}

			var assemblyHash = $"{assemblyName}@{assemblyVersion}".ToLowerInvariant();

			return store.Decisions.Any(entry => entry.ScopeKind == TrustDecisionScopeKind.Assembly &&
												string.Equals(entry.SubjectHash, assemblyHash, StringComparison.OrdinalIgnoreCase) &&
												IsApprovalDecision(entry) &&
												!IsExpired(entry));
		}

		/// <summary>
		/// Adds an assembly trust decision.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <param name="assemblyName">Assembly name (e.g., package ID).</param>
		/// <param name="assemblyVersion">Assembly version.</param>
		/// <param name="reason">Trust reason.</param>
		/// <param name="userSid">Acting user identity.</param>
		/// <param name="assemblySigner">Assembly signer display name when known.</param>
		/// <param name="assemblyIssuer">Assembly certificate issuer when known.</param>
		/// <param name="assemblySubject">Assembly certificate subject when known.</param>
		/// <param name="expiresAtUtc">Optional expiration timestamp.</param>
		public void AddAssemblyTrust(
			string path,
			string assemblyName,
			string assemblyVersion,
			string reason,
			string userSid,
			string assemblySigner = "",
			string assemblyIssuer = "",
			string assemblySubject = "",
			DateTimeOffset? expiresAtUtc = null)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			if (assemblyName == null)
			{
				throw new ArgumentNullException(nameof(assemblyName));
			}

			if (assemblyVersion == null)
			{
				throw new ArgumentNullException(nameof(assemblyVersion));
			}

			if (reason == null)
			{
				throw new ArgumentNullException(nameof(reason));
			}

			if (userSid == null)
			{
				throw new ArgumentNullException(nameof(userSid));
			}

			var assemblyHash = $"{assemblyName}@{assemblyVersion}".ToLowerInvariant();

			var entry = new TrustDecisionEntry
			{
				DecisionId = Guid.NewGuid().ToString("N"),
				Scope = "Assembly",
				SubjectHash = assemblyHash,
				AssemblySigner = assemblySigner ?? string.Empty,
				AssemblyIssuer = assemblyIssuer ?? string.Empty,
				AssemblySubject = assemblySubject ?? string.Empty,
				Decision = "Trust",
				Reason = reason,
				UserSid = userSid,
				CreatedAtUtc = DateTimeOffset.UtcNow,
				ExpiresAtUtc = expiresAtUtc
			};

			AddDecision(path, entry);
		}

		/// <summary>
		/// Adds a NuGet package-level trust decision using the computed directory hash.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <param name="packageId">Package ID.</param>
		/// <param name="packageVersion">Package version.</param>
		/// <param name="packageHash">Precalculated directory hash.</param>
		/// <param name="reason">Trust reason.</param>
		/// <param name="userSid">Acting user identity.</param>
		/// <param name="expiresAtUtc">Optional expiration timestamp.</param>
		public void AddPackageTrust(
			string path,
			string packageId,
			string packageVersion,
			string packageHash,
			string reason,
			string userSid,
			DateTimeOffset? expiresAtUtc = null)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			if (packageId == null)
			{
				throw new ArgumentNullException(nameof(packageId));
			}

			if (packageVersion == null)
			{
				throw new ArgumentNullException(nameof(packageVersion));
			}

			if (packageHash == null)
			{
				throw new ArgumentNullException(nameof(packageHash));
			}

			if (reason == null)
			{
				throw new ArgumentNullException(nameof(reason));
			}

			if (userSid == null)
			{
				throw new ArgumentNullException(nameof(userSid));
			}

			var entry = new TrustDecisionEntry
			{
				DecisionId     = Guid.NewGuid().ToString("N"),
				Scope          = "Package",
				SubjectHash    = packageHash,
				AssemblySigner = $"{packageId}@{packageVersion}".ToLowerInvariant(),
				Decision       = "Trust",
				Reason         = reason,
				UserSid        = userSid,
				CreatedAtUtc   = DateTimeOffset.UtcNow,
				ExpiresAtUtc   = expiresAtUtc
			};

			AddDecision(path, entry);
		}

		/// <summary>
		/// Removes assembly trust decisions that match the provided assembly name and version.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <param name="assemblyName">Assembly name (e.g., package ID).</param>
		/// <param name="assemblyVersion">Assembly version.</param>
		/// <param name="reason">Revocation reason.</param>
		/// <param name="userSid">Acting user identity.</param>
		/// <returns>The number of removed decisions.</returns>
		public int RemoveAssemblyTrust(string path, string assemblyName, string assemblyVersion, string reason, string userSid)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			if (assemblyName == null)
			{
				throw new ArgumentNullException(nameof(assemblyName));
			}

			if (assemblyVersion == null)
			{
				throw new ArgumentNullException(nameof(assemblyVersion));
			}

			if (reason == null)
			{
				throw new ArgumentNullException(nameof(reason));
			}

			if (userSid == null)
			{
				throw new ArgumentNullException(nameof(userSid));
			}

			var assemblyHash = $"{assemblyName}@{assemblyVersion}".ToLowerInvariant();

				return RemoveDecisionsBySubject(path, assemblyHash, reason, userSid);
			}

			/// <summary>
			/// Adds a signer-level trust decision that approves all assemblies bearing the same certificate signer.
			/// </summary>
			/// <param name="path">Trust store path.</param>
			/// <param name="signerThumbprint">Certificate thumbprint — used as the canonical trust key when available.</param>
			/// <param name="signerSubject">Certificate Subject DN.</param>
			/// <param name="signerDisplayName">Human-readable signer name.</param>
			/// <param name="issuer">Certificate issuer.</param>
			/// <param name="serialNumber">Certificate serial number.</param>
			/// <param name="reason">Trust reason.</param>
			/// <param name="userSid">Acting user identity.</param>
			/// <param name="expiresAtUtc">Optional expiration timestamp.</param>
			public void AddSignerTrust(
				string path,
				string signerThumbprint,
				string signerSubject,
				string signerDisplayName,
				string issuer,
				string serialNumber,
				string reason,
				string userSid,
				DateTimeOffset? expiresAtUtc = null)
			{
				if (path == null)
				{
					throw new ArgumentNullException(nameof(path));
				}

				if (signerThumbprint == null)
				{
					throw new ArgumentNullException(nameof(signerThumbprint));
				}

				if (signerSubject == null)
				{
					throw new ArgumentNullException(nameof(signerSubject));
				}

				if (reason == null)
				{
					throw new ArgumentNullException(nameof(reason));
				}

				if (userSid == null)
				{
					throw new ArgumentNullException(nameof(userSid));
				}

				var signerKey = GetSignerTrustKey(signerThumbprint, signerSubject, issuer, serialNumber);

				var entry = new TrustDecisionEntry
				{
					DecisionId           = Guid.NewGuid().ToString("N"),
					Scope                = "Signer",
					SubjectHash          = signerKey,
					AssemblySigner       = signerDisplayName ?? string.Empty,
					AssemblyIssuer       = issuer ?? string.Empty,
					AssemblySubject      = signerSubject,
					AssemblyThumbprint   = signerThumbprint ?? string.Empty,
					AssemblySerialNumber = serialNumber ?? string.Empty,
					Decision             = "Trust",
					Reason               = reason,
					UserSid              = userSid,
					CreatedAtUtc         = DateTimeOffset.UtcNow,
					ExpiresAtUtc         = expiresAtUtc
				};

				AddDecision(path, entry);
			}

			/// <summary>
			/// Determines whether the given certificate signer is trusted in the store.
			/// </summary>
			/// <param name="store">Trust store document.</param>
			/// <param name="signerThumbprint">Certificate thumbprint.</param>
			/// <param name="signerSubject">Certificate Subject DN.</param>
			/// <param name="signerIssuer">Certificate issuer.</param>
			/// <param name="signerSerialNumber">Certificate serial number.</param>
			/// <returns><see langword="true"/> when the signer is trusted; otherwise <see langword="false"/>.</returns>
			public bool IsSignerTrusted(TrustStoreDocument store, string signerThumbprint, string signerSubject, string signerIssuer, string signerSerialNumber)
			{
				if (store == null)
				{
					throw new ArgumentNullException(nameof(store));
				}

				if (string.IsNullOrWhiteSpace(signerThumbprint) && string.IsNullOrWhiteSpace(signerSubject))
				{
					return false;
				}

				var signerKey = GetSignerTrustKey(signerThumbprint, signerSubject, signerIssuer, signerSerialNumber);

				return store.Decisions.Any(entry =>
					entry.ScopeKind == TrustDecisionScopeKind.Signer &&
					IsApprovalDecision(entry) &&
					!IsExpired(entry) &&
					string.Equals(entry.SubjectHash, signerKey, StringComparison.OrdinalIgnoreCase));
			}

			/// <summary>
			/// Determines whether a finding is approved by assembly-level trust.
			/// </summary>
		/// <param name="store">Trust store document.</param>
		/// <param name="packageId">Package ID.</param>
		/// <param name="packageVersion">Package version.</param>
		/// <returns><see langword="true"/> when the assembly is approved; otherwise <see langword="false"/>.</returns>
		public bool IsFindingApprovedByAssembly(TrustStoreDocument store, string packageId, string packageVersion)
		{
			if (store == null)
			{
				throw new ArgumentNullException(nameof(store));
			}

			if (string.IsNullOrWhiteSpace(packageId) || string.IsNullOrWhiteSpace(packageVersion))
			{
				return false;
			}

			return IsAssemblyApproved(store, packageId, packageVersion);
		}

		/// <summary>
		/// Determines whether a finding is approved by package-level directory hash trust.
		/// </summary>
		/// <param name="store">Trust store document.</param>
		/// <param name="packageId">Package ID.</param>
		/// <param name="packageVersion">Package version.</param>
		/// <returns><see langword="true"/> when the package is approved and the hash matches; otherwise <see langword="false"/>.</returns>
		public bool IsFindingApprovedByPackage(TrustStoreDocument store, string packageId, string packageVersion)
		{
			if (store == null)
			{
				throw new ArgumentNullException(nameof(store));
			}

			if (string.IsNullOrWhiteSpace(packageId) || string.IsNullOrWhiteSpace(packageVersion))
			{
				return false;
			}

			var subjectKey = $"{packageId}@{packageVersion}".ToLowerInvariant();

			var packageDecision = store.Decisions.FirstOrDefault(entry =>
				entry.ScopeKind == TrustDecisionScopeKind.Package &&
				string.Equals(entry.AssemblySigner, subjectKey, StringComparison.OrdinalIgnoreCase) &&
				IsApprovalDecision(entry) &&
				!IsExpired(entry));

			if (packageDecision == null)
			{
				return false;
			}

			var userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

			var packageDir = Path.Combine(userHome, ".nuget", "packages", packageId.ToLowerInvariant(), packageVersion.ToLowerInvariant());

			if (!Directory.Exists(packageDir))
			{
				return false;
			}

			var currentHash = CalculatePackageDirectoryHash(packageDir);

			if (string.IsNullOrWhiteSpace(currentHash))
			{
				return false;
			}

			return string.Equals(packageDecision.SubjectHash, currentHash, StringComparison.OrdinalIgnoreCase);
		}

		/// <summary>
		/// Determines whether a finding fingerprint is approved in trust store.
		/// </summary>
		/// <param name="store">Trust store document.</param>
		/// <param name="fingerprint">Finding fingerprint.</param>
		/// <returns><see langword="true"/> when approved; otherwise <see langword="false"/>.</returns>
		public bool IsFingerprintApproved(TrustStoreDocument store, string fingerprint)
		{
			if (store == null)
			{
				throw new ArgumentNullException(nameof(store));
			}

			if (fingerprint == null)
			{
				throw new ArgumentNullException(nameof(fingerprint));
			}

			return store.Decisions.Any(entry => entry.ScopeKind == TrustDecisionScopeKind.Finding &&
												string.Equals(entry.SubjectHash, fingerprint, StringComparison.OrdinalIgnoreCase) &&
												IsApprovalDecision(entry) &&
												!IsExpired(entry));
		}

		/// <summary>
		/// Determines whether a finding is approved by finding-level or file-level trust.
		/// </summary>
		/// <param name="store">Trust store document.</param>
		/// <param name="fingerprint">Finding fingerprint.</param>
		/// <param name="normalizedFileHash">Normalized file hash for the finding source file.</param>
		/// <param name="trustContext">Scan trust context.</param>
		/// <param name="policyProfile">Active policy profile.</param>
		/// <returns><see langword="true"/> when the finding is approved; otherwise <see langword="false"/>.</returns>
		public bool IsFindingApproved(TrustStoreDocument store, string fingerprint, string normalizedFileHash, ScanTrustContext trustContext, string policyProfile)
		{
			if (store == null)
			{
				throw new ArgumentNullException(nameof(store));
			}

			if (fingerprint == null)
			{
				throw new ArgumentNullException(nameof(fingerprint));
			}

			if (normalizedFileHash == null)
			{
				throw new ArgumentNullException(nameof(normalizedFileHash));
			}

			if (trustContext == null)
			{
				throw new ArgumentNullException(nameof(trustContext));
			}

			if (policyProfile == null)
			{
				throw new ArgumentNullException(nameof(policyProfile));
			}

			return store.Decisions.Any(entry =>
				IsApprovalDecision(entry) &&
				!IsExpired(entry) &&
				MatchesTrustContext(entry, trustContext, policyProfile) &&
				(
					(entry.ScopeKind == TrustDecisionScopeKind.Finding && string.Equals(entry.SubjectHash, fingerprint, StringComparison.OrdinalIgnoreCase)) ||
					(entry.ScopeKind == TrustDecisionScopeKind.File && string.Equals(entry.SubjectHash, normalizedFileHash, StringComparison.OrdinalIgnoreCase))
				));
		}

		/// <summary>
		/// Determines whether repository trust matches the provided remote and commit.
		/// </summary>
		/// <param name="store">Trust store document.</param>
		/// <param name="repositoryRemote">Repository remote.</param>
		/// <param name="commitSha">Commit SHA.</param>
		/// <param name="policyProfile">Optional policy profile.</param>
		/// <returns><see langword="true"/> when a matching active repository or baseline trust decision exists; otherwise <see langword="false"/>.</returns>
		public bool IsRepositoryTrusted(TrustStoreDocument store, string repositoryRemote, string branch, string commitSha, string policyProfile)
		{
			if (store == null)
			{
				throw new ArgumentNullException(nameof(store));
			}

			if (repositoryRemote == null)
			{
				throw new ArgumentNullException(nameof(repositoryRemote));
			}

			if (branch == null)
			{
				throw new ArgumentNullException(nameof(branch));
			}

			if (commitSha == null)
			{
				throw new ArgumentNullException(nameof(commitSha));
			}

			if (policyProfile == null)
			{
				throw new ArgumentNullException(nameof(policyProfile));
			}

			return store.Decisions.Any(entry =>
				(entry.ScopeKind == TrustDecisionScopeKind.Repository || entry.ScopeKind == TrustDecisionScopeKind.Baseline) &&
				IsApprovalDecision(entry) &&
				!IsExpired(entry) &&
				string.Equals(entry.RepositoryRemote, repositoryRemote, StringComparison.OrdinalIgnoreCase) &&
				string.Equals(entry.CommitSha, commitSha, StringComparison.OrdinalIgnoreCase) &&
				(string.IsNullOrWhiteSpace(entry.Branch) || string.Equals(entry.Branch, branch, StringComparison.OrdinalIgnoreCase)) &&
				(string.IsNullOrWhiteSpace(entry.PolicyProfile) || string.Equals(entry.PolicyProfile, policyProfile, StringComparison.OrdinalIgnoreCase)));
		}

		/// <summary>
		/// Determines whether a trust entry matches the active scan trust context.
		/// </summary>
		/// <param name="entry">The trust entry.</param>
		/// <param name="trustContext">The scan trust context.</param>
		/// <param name="policyProfile">The active policy profile.</param>
		/// <returns><see langword="true"/> when the trust entry applies to the current context; otherwise <see langword="false"/>.</returns>
		private static bool MatchesTrustContext(TrustDecisionEntry entry, ScanTrustContext trustContext, string policyProfile)
		{
			if (!string.IsNullOrWhiteSpace(entry.RepositoryRemote) && !string.Equals(entry.RepositoryRemote, trustContext.RepositoryRemote, StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}

			if (!string.IsNullOrWhiteSpace(entry.Branch) && !string.Equals(entry.Branch, trustContext.Branch, StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}

			if (!string.IsNullOrWhiteSpace(entry.CommitSha) && !string.Equals(entry.CommitSha, trustContext.CommitSha, StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}

			if (!string.IsNullOrWhiteSpace(entry.PolicyProfile) && !string.Equals(entry.PolicyProfile, policyProfile, StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}

			return true;
		}

		/// <summary>
		/// Builds the canonical signer trust key.
		/// </summary>
		/// <param name="thumbprint">Certificate thumbprint.</param>
		/// <param name="subject">Certificate subject DN.</param>
		/// <param name="issuer">Certificate issuer.</param>
		/// <param name="serialNumber">Certificate serial number.</param>
		/// <returns>A canonical signer identity string.</returns>
		private static string GetSignerTrustKey(string thumbprint, string subject, string issuer, string serialNumber)
		{
			if (!string.IsNullOrWhiteSpace(thumbprint))
			{
				return NormalizeThumbprint(thumbprint);
			}

			return $"{NormalizeIdentityPart(subject)}|{NormalizeIdentityPart(issuer)}|{NormalizeIdentityPart(serialNumber)}";
		}

		/// <summary>
		/// Determines whether a legacy signer entry matches using the old Subject-only storage.
		/// </summary>
		/// <param name="entry">The trust entry.</param>
		/// <param name="signerSubject">Certificate Subject DN.</param>
		/// <param name="signerIssuer">Certificate issuer.</param>
		/// <param name="signerSerialNumber">Certificate serial number.</param>
		/// <returns><see langword="true"/> when a legacy entry matches; otherwise <see langword="false"/>.</returns>
		private static bool IsLegacySignerMatch(TrustDecisionEntry entry, string signerSubject, string signerIssuer, string signerSerialNumber)
		{
			if (string.IsNullOrWhiteSpace(signerSubject))
			{
				return false;
			}

			return string.Equals(entry.SubjectHash, signerSubject, StringComparison.OrdinalIgnoreCase) &&
				string.IsNullOrWhiteSpace(entry.AssemblyThumbprint) &&
				string.IsNullOrWhiteSpace(entry.AssemblySerialNumber) &&
				(string.IsNullOrWhiteSpace(entry.AssemblyIssuer) || string.Equals(entry.AssemblyIssuer, signerIssuer, StringComparison.OrdinalIgnoreCase)) &&
				(string.IsNullOrWhiteSpace(entry.AssemblySubject) || string.Equals(entry.AssemblySubject, signerSubject, StringComparison.OrdinalIgnoreCase)) &&
				(string.IsNullOrWhiteSpace(signerSerialNumber) || string.IsNullOrWhiteSpace(entry.AssemblySerialNumber) || string.Equals(entry.AssemblySerialNumber, signerSerialNumber, StringComparison.OrdinalIgnoreCase));
		}

		/// <summary>
		/// Determines whether a trust entry represents an approval decision.
		/// </summary>
		/// <param name="entry">The trust entry.</param>
		/// <returns><see langword="true"/> when the decision is approving; otherwise <see langword="false"/>.</returns>
		private static bool IsApprovalDecision(TrustDecisionEntry entry)
		{
			return entry.DecisionKind == TrustDecisionKind.Trust ||
				   entry.DecisionKind == TrustDecisionKind.TrustUntilChanged ||
				   entry.DecisionKind == TrustDecisionKind.DismissFinding;
		}

		/// <summary>
		/// Normalizes thumbprints for comparison.
		/// </summary>
		/// <param name="value">Thumbprint value.</param>
		/// <returns>Normalized thumbprint.</returns>
		private static string NormalizeThumbprint(string value)
		{
			return new string(value.Where(ch => !char.IsWhiteSpace(ch) && ch != ':').ToArray()).ToUpperInvariant();
		}

		/// <summary>
		/// Normalizes identity text for comparison.
		/// </summary>
		/// <param name="value">Identity value.</param>
		/// <returns>Normalized identity text.</returns>
		private static string NormalizeIdentityPart(string value)
		{
			return string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().ToUpperInvariant();
		}

		/// <summary>
		/// Determines whether a trust entry has expired.
		/// </summary>
		/// <param name="entry">The trust entry.</param>
		/// <returns><see langword="true"/> when the entry has expired; otherwise <see langword="false"/>.</returns>
		private static bool IsExpired(TrustDecisionEntry entry)
		{
			return entry.ExpiresAtUtc.HasValue && entry.ExpiresAtUtc.Value <= DateTimeOffset.UtcNow;
		}

		/// <summary>
		/// Gets default user trust store path.
		/// </summary>
		/// <returns>The user trust store path.</returns>
		public string GetDefaultUserTrustPath()
		{
			var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

			return Path.Combine(localData, "MSBuildGuard", "trust.json");
		}

		/// <summary>
		/// Gets the solution-level trust store path.
		/// </summary>
		/// <param name="solutionPath">The full solution path.</param>
		/// <returns>The solution-level trust store path.</returns>
		public string GetSolutionTrustPath(string solutionPath)
		{
			if (solutionPath == null)
			{
				throw new ArgumentNullException(nameof(solutionPath));
			}

			var solutionDirectory = Path.GetDirectoryName(solutionPath);

			if (string.IsNullOrWhiteSpace(solutionDirectory))
			{
				throw new InvalidOperationException("Solution path must include a valid directory.");
			}

			return Path.Combine(solutionDirectory, ".msbuildguard", "trust.json");
		}

		/// <summary>
		/// Gets the project-level trust store path.
		/// </summary>
		/// <param name="projectPath">The full project path.</param>
		/// <returns>The project-level trust store path.</returns>
		public string GetProjectTrustPath(string projectPath)
		{
			if (projectPath == null)
			{
				throw new ArgumentNullException(nameof(projectPath));
			}

			var projectDirectory = Path.GetDirectoryName(projectPath);

			if (string.IsNullOrWhiteSpace(projectDirectory))
			{
				throw new InvalidOperationException("Project path must include a valid directory.");
			}

			return Path.Combine(projectDirectory, ".msbuildguard", "trust.json");
		}

		/// <summary>
		/// Loads and merges trust decisions from user, solution, and project scopes.
		/// </summary>
		/// <param name="userTrustPath">The user-level trust store path.</param>
		/// <param name="solutionPath">Optional solution path for solution-level trust.</param>
		/// <param name="projectPath">Optional project path for project-level trust.</param>
		/// <returns>A merged trust store document containing all active decisions.</returns>
		public TrustStoreDocument LoadMergedTrustStore(string userTrustPath, string? solutionPath, string? projectPath)
		{
			if (userTrustPath == null)
			{
				throw new ArgumentNullException(nameof(userTrustPath));
			}

			var merged = new TrustStoreDocument();

			AppendDecisions(merged, Load(userTrustPath));

			if (!string.IsNullOrWhiteSpace(solutionPath))
			{
				AppendDecisions(merged, Load(GetSolutionTrustPath(solutionPath!)));
			}

			if (!string.IsNullOrWhiteSpace(projectPath))
			{
				AppendDecisions(merged, Load(GetProjectTrustPath(projectPath!)));
			}

			return merged;
		}

		/// <summary>
		/// Gets the audit-log path associated with a trust store path.
		/// </summary>
		/// <param name="trustStorePath">Trust store path.</param>
		/// <returns>The audit-log path.</returns>
		public string GetAuditPathForStore(string trustStorePath)
		{
			if (trustStorePath == null)
			{
				throw new ArgumentNullException(nameof(trustStorePath));
			}

			return trustStorePath + ".audit.jsonl";
		}

		/// <summary>
		/// Appends trust decisions from a source document into a destination document.
		/// </summary>
		/// <param name="destination">The destination trust document.</param>
		/// <param name="source">The source trust document.</param>
		private static void AppendDecisions(TrustStoreDocument destination, TrustStoreDocument source)
		{
			if (destination == null)
			{
				throw new ArgumentNullException(nameof(destination));
			}

			if (source == null)
			{
				throw new ArgumentNullException(nameof(source));
			}

			foreach (var decision in source.Decisions)
			{
				destination.Decisions.Add(decision);
			}
		}

		/// <summary>
		/// Appends a trust audit event to the audit log associated with the specified trust store, ensuring that the integrity of the audit chain is maintained through hash linking of events.
		/// </summary>
		/// <param name="trustStorePath"></param>
		/// <param name="auditEvent"></param>
		private void AppendAuditEvent(string trustStorePath, TrustAuditEvent auditEvent)
		{
			var auditPath = GetAuditPathForStore(trustStorePath);
			var directory = Path.GetDirectoryName(auditPath);

			if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
			{
				Directory.CreateDirectory(directory);
			}

			string previousEventHash = string.Empty;

			if (File.Exists(auditPath))
			{
				var lastLine = File.ReadAllLines(auditPath).LastOrDefault(line => !string.IsNullOrWhiteSpace(line));

				if (!string.IsNullOrWhiteSpace(lastLine))
				{
					var lastEvent = JsonSerializer.Deserialize<TrustAuditEvent>(lastLine, AuditSerializerOptions);

					if (lastEvent != null)
					{
						previousEventHash = ComputeEventHash(lastEvent);
					}
				}
			}

			auditEvent.PreviousEventHash = previousEventHash;

			var payload = JsonSerializer.Serialize(auditEvent, AuditSerializerOptions) + Environment.NewLine;

			File.AppendAllText(auditPath, payload);
		}

		/// <summary>
		/// Creates a trust audit event based on the provided decision entry and context information.
		/// </summary>
		/// <param name="eventKind"></param>
		/// <param name="entry"></param>
		/// <param name="reason"></param>
		/// <param name="userSid"></param>
		/// <returns></returns>
		private static TrustAuditEvent CreateAuditEvent(string eventKind, TrustDecisionEntry entry, string reason, string userSid)
		{
			return new TrustAuditEvent
			{
				DecisionId = entry.DecisionId,
				EventId = Guid.NewGuid().ToString("N"),
				EventKind = eventKind,
				OccurredAtUtc = DateTimeOffset.UtcNow,
				PreviousEventHash = string.Empty,
				Reason = reason,
				Scope = entry.Scope,
				SubjectHash = entry.SubjectHash,
				UserSid = userSid
			};
		}

		/// <summary>
		/// Computes a SHA256 hash of the serialized audit event for integrity chaining.
		/// </summary>
		/// <param name="auditEvent"></param>
		/// <returns></returns>
		private static string ComputeEventHash(TrustAuditEvent auditEvent)
		{
			if (auditEvent == null)
			{
				return string.Empty;
			}

			var json = JsonSerializer.Serialize(auditEvent, AuditSerializerOptions);
			var bytes = Encoding.UTF8.GetBytes(json);

			using (var sha256 = SHA256.Create())
			{
				var hashBytes = sha256.ComputeHash(bytes);

				return BitConverter.ToString(hashBytes).Replace("-", string.Empty);
			}
		}

		/// <summary>
		/// Validates the integrity of the audit event chain by ensuring that each event's PreviousEventHash matches the computed hash of the prior event.
		/// </summary>
		/// <param name="events"></param>
		/// <exception cref="InvalidOperationException"></exception>
		private static void ValidateAuditChainIntegrity(IList<TrustAuditEvent> events)
		{
			if (events.Count == 0)
			{
				return;
			}

			for (int i = 0; i < events.Count; i++)
			{
				var current = events[i];

				if (i == 0)
				{
					if (!string.IsNullOrEmpty(current.PreviousEventHash))
					{
						throw new InvalidOperationException("Audit trail integrity compromised: first event has non-empty PreviousEventHash.");
					}
				}
				else
				{
					var prior = events[i - 1];
					var expectedHash = ComputeEventHash(prior);

					if (!string.Equals(current.PreviousEventHash, expectedHash, StringComparison.Ordinal))
					{
						throw new InvalidOperationException($"Audit trail integrity compromised at event {i}: chain hash mismatch. Event may have been deleted or reordered.");
					}
				}
			}
		}

		/// <summary>
		/// Calculates a deterministic cryptographic hash of a package directory by traversing all files,
		/// sorting them by relative path, hashing each file's content, and combining them.
		/// </summary>
		/// <param name="packageDirectoryPath">The absolute path to the package directory.</param>
		/// <returns>A SHA256 hex string representing the package directory state, or empty string on error.</returns>
		public static string CalculatePackageDirectoryHash(string packageDirectoryPath)
		{
			if (string.IsNullOrWhiteSpace(packageDirectoryPath) || !Directory.Exists(packageDirectoryPath))
			{

				return string.Empty;
			}

			try
			{
				var files = Directory.GetFiles(packageDirectoryPath, "*", SearchOption.AllDirectories);

				var relativeFiles = new List<(string RelativePath, string AbsolutePath)>();

				foreach (var file in files)
				{
					var relativePath = file.Substring(packageDirectoryPath.Length)
						.TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
						.Replace('\\', '/');

					relativeFiles.Add((relativePath, file));
				}

				relativeFiles.Sort((x, y) => string.Compare(x.RelativePath, y.RelativePath, StringComparison.Ordinal));

				using (var sha256 = SHA256.Create())
				{
					var builder = new StringBuilder();

					foreach (var fileInfo in relativeFiles)
					{
						byte[] fileHash;

						using (var stream = File.OpenRead(fileInfo.AbsolutePath))
						{
							fileHash = sha256.ComputeHash(stream);
						}

						var fileHashHex = BitConverter.ToString(fileHash).Replace("-", "").ToLowerInvariant();

						builder.Append(fileInfo.RelativePath).Append(':').Append(fileHashHex).Append('\n');
					}

					var combinedBytes = Encoding.UTF8.GetBytes(builder.ToString());

					var finalHash = sha256.ComputeHash(combinedBytes);

					return BitConverter.ToString(finalHash).Replace("-", "").ToLowerInvariant();
				}
			}
			catch
			{

				return string.Empty;
			}
		}
	}
}

