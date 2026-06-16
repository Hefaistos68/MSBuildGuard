using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
		/// <summary>
		/// Fallback symmetric signing key used when repository trust sharing is enabled.
		/// </summary>
		private const string TrustStoreSigningKey = "MSBuildGuard.TrustStore.v1";

		/// <summary>
		/// Serializer options for trust store documents.
		/// </summary>
		private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
		{
			WriteIndented               = true,
			PropertyNameCaseInsensitive = true,
			Converters                  = { new JsonStringEnumConverter() }
		};

		/// <summary>
		/// Serializer options for line-delimited audit events.
		/// </summary>
		private static readonly JsonSerializerOptions AuditSerializerOptions = new JsonSerializerOptions
		{
			WriteIndented = false
		};

		/// <summary>
		/// In-memory cache of calculated package directory hashes by absolute directory path.
		/// </summary>
		private readonly Dictionary<string, string> packageDirectoryHashCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

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

			if (!isEnvelopeFormat)
			{
				throw new InvalidDataException("Trust store must be signed. Unsigned trust stores are not allowed.");
			}

			var signingKey = GetSigningKeyForPath(path);
			string? trustPayload;
			var isEnvelopeSigned = signatureService.TryVerifyAndExtract<string>(payload, signingKey, out trustPayload) && !string.IsNullOrWhiteSpace(trustPayload);

			if (!isEnvelopeSigned)
			{
				throw new InvalidDataException("Trust store signature validation failed. Do not modify the contents of this file manually.");
			}

			// Verify optional Asymmetric signature
			var hasAsymmetricSignature = TryReadSignatureRecord(path, out _);

			if (hasAsymmetricSignature)
			{
				ValidateSignedTrust(path);
				PinRepositoryAsAsymmetricRequired(path);
			}
			else
			{
				var solutionDir = Path.GetDirectoryName(path);
				var isSolutionOrProjectScope = !string.IsNullOrWhiteSpace(solutionDir) && (solutionDir.Contains(".msbuildguard") || path.Contains(".msbuildguard"));

				if (CoreSettings.EnforceAsymmetricSignatures && isSolutionOrProjectScope)
				{
					throw new InvalidDataException("Asymmetric signature is required but missing.");
				}

				if (IsRepositoryPinnedAsAsymmetricRequired(path) && isSolutionOrProjectScope)
				{
					throw new InvalidDataException("Asymmetric signature is required for this pinned repository but is missing.");
				}
			}

			var trust = JsonSerializer.Deserialize<TrustStoreDocument>(trustPayload!, SerializerOptions);

			if (trust == null)
			{
				throw new InvalidDataException("Unable to deserialize decrypted trust store content.");
			}

			// Verify audit trail integrity if the audit file exists
			var auditPath = GetAuditPathForStore(path);

			if (File.Exists(auditPath))
			{
				try
				{
					ReadAudit(auditPath);
				}
				catch (Exception ex)
				{
					throw new InvalidDataException($"Audit trail integrity validation failed for '{path}': {ex.Message}", ex);
				}
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

			var hasAsymmetricSignature = TryReadSignatureRecord(path, out var signatureRecord);
			string? signingThumbprint = null;

			if (hasAsymmetricSignature)
			{
				signingThumbprint = signatureRecord.SigningCertificateThumbprint;
			}
			else
			{
				var solutionDir = Path.GetDirectoryName(path);
				var isSolutionOrProjectScope = !string.IsNullOrWhiteSpace(solutionDir) && (solutionDir.Contains(".msbuildguard") || path.Contains(".msbuildguard"));

				if (isSolutionOrProjectScope && (CoreSettings.EnforceAsymmetricSignatures || IsRepositoryPinnedAsAsymmetricRequired(path)))
				{
					signingThumbprint = ResolveSigningCertificateThumbprint(null);
				}
			}

			var trustPayload = JsonSerializer.Serialize(document, SerializerOptions);
			var signingKey = GetSigningKeyForPath(path);
			var payload = new JsonSignatureService().CreateSignedEnvelopeJson(trustPayload, signingKey);

			WriteAllTextAtomic(path, payload);

			if (signingThumbprint != null)
			{
				Sign(path, signingThumbprint);
			}
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

			var currentHash = this.GetCachedPackageDirectoryHash(packageDir);

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
		/// <param name="branch">Repository branch.</param>
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
		/// Appends a trust audit event to the audit log associated with the specified trust store,
		/// preserving hash-chain continuity with the previous event.
		/// </summary>
		/// <param name="trustStorePath">Trust store path used to resolve the audit log location.</param>
		/// <param name="auditEvent">Audit event to append.</param>
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
		/// Creates a trust audit event from a trust decision and operation context.
		/// </summary>
		/// <param name="eventKind">Audit operation kind.</param>
		/// <param name="entry">Decision entry associated with the operation.</param>
		/// <param name="reason">Human-readable operation reason.</param>
		/// <param name="userSid">Security identifier of the acting user.</param>
		/// <returns>A populated audit event instance.</returns>
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
		/// Computes a SHA256 hash of a serialized audit event for integrity chaining.
		/// </summary>
		/// <param name="auditEvent">Audit event to hash.</param>
		/// <returns>Uppercase hexadecimal SHA256 hash, or empty when the input is null.</returns>
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
		/// Validates the integrity of the audit event chain by ensuring each event references
		/// the computed hash of its predecessor.
		/// </summary>
		/// <param name="events">Audit events in persisted order.</param>
		/// <exception cref="InvalidOperationException">Thrown when chain linkage is invalid.</exception>
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

		/// <summary>
		/// Gets the cached directory hash for a package directory, calculating it first if not cached.
		/// </summary>
		/// <param name="packageDirectoryPath">Path to package directory.</param>
		/// <returns>The calculated or cached package hash.</returns>
		private string GetCachedPackageDirectoryHash(string packageDirectoryPath)
		{
			if (string.IsNullOrWhiteSpace(packageDirectoryPath))
			{
				return string.Empty;
			}

			lock (this.packageDirectoryHashCache)
			{
				if (this.packageDirectoryHashCache.TryGetValue(packageDirectoryPath, out var cachedHash))
				{
					return cachedHash;
				}

				var hash = CalculatePackageDirectoryHash(packageDirectoryPath);

				this.packageDirectoryHashCache[packageDirectoryPath] = hash;

				return hash;
			}
		}

		/// <summary>
		/// Current supported version of persisted trust signature metadata.
		/// </summary>
		private const int TrustSignatureVersion = 1;

		/// <summary>
		/// Signature algorithm identifier used for trust-store signing.
		/// </summary>
		private const string TrustSignatureAlgorithm = "RSASSA-PKCS1-v1_5-SHA256";

		/// <summary>
		/// Logical stream name for trust signature metadata.
		/// </summary>
		private const string TrustSignatureStreamName = "msbuildguard.trust.signature";

		/// <summary>
		/// Serialized metadata describing a trust-store asymmetric signature.
		/// </summary>
		private sealed class TrustSignatureRecord
		{
			/// <summary>
			/// Metadata schema version.
			/// </summary>
			public int Version { get; set; } = 1;

			/// <summary>
			/// Signature algorithm identifier.
			/// </summary>
			public string Algorithm { get; set; } = TrustSignatureAlgorithm;

			/// <summary>
			/// Thumbprint of the certificate that produced the signature.
			/// </summary>
			public string SigningCertificateThumbprint { get; set; } = string.Empty;

			/// <summary>
			/// Base64 signature payload.
			/// </summary>
			public string Signature { get; set; } = string.Empty;
		}

		/// <summary>
		/// Signs a trust store file using a certificate thumbprint and stores signature metadata next to the trust file.
		/// </summary>
		/// <param name="trustPath">Path to the trust store file.</param>
		/// <param name="signingCertificateThumbprint">Optional certificate thumbprint override.</param>
		public void Sign(string trustPath, string? signingCertificateThumbprint)
		{
			if (trustPath == null)
			{
				throw new ArgumentNullException(nameof(trustPath));
			}

			if (!File.Exists(trustPath))
			{
				throw new FileNotFoundException("Trust file was not found.", trustPath);
			}

			var thumbprint = ResolveSigningCertificateThumbprint(signingCertificateThumbprint);
			var certificate = LoadSigningCertificateOrThrow(thumbprint);
			var trustBytes = File.ReadAllBytes(trustPath);
			var signatureBytes = ComputeSignature(trustBytes, certificate);
			var signatureRecord = new TrustSignatureRecord
			{
				Version = TrustSignatureVersion,
				Algorithm = TrustSignatureAlgorithm,
				SigningCertificateThumbprint = thumbprint,
				Signature = Convert.ToBase64String(signatureBytes)
			};
			var signaturePath = GetSignatureStreamPath(trustPath);
			var payload = JsonSerializer.Serialize(signatureRecord);

			File.WriteAllText(signaturePath, payload);
		}

		/// <summary>
		/// Validates the asymmetric signature for a trust store file.
		/// </summary>
		/// <param name="trustPath">Path to the trust store file.</param>
		public void ValidateSignedTrust(string trustPath)
		{
			if (trustPath == null)
			{
				throw new ArgumentNullException(nameof(trustPath));
			}

			if (!File.Exists(trustPath))
			{
				throw new FileNotFoundException("Trust file was not found.", trustPath);
			}

			if (!TryReadSignatureRecord(trustPath, out var signatureRecord))
			{
				throw new InvalidDataException("Trust signature is missing.");
			}

			if (signatureRecord.Version != TrustSignatureVersion)
			{
				throw new InvalidDataException($"Trust signature stream uses unsupported version '{signatureRecord.Version}'.");
			}

			if (!string.Equals(signatureRecord.Algorithm, TrustSignatureAlgorithm, StringComparison.OrdinalIgnoreCase))
			{
				throw new InvalidDataException($"Trust signature stream uses unsupported algorithm '{signatureRecord.Algorithm}'.");
			}

			if (string.IsNullOrWhiteSpace(signatureRecord.Signature))
			{
				throw new InvalidDataException("Trust signature is missing.");
			}

			if (string.IsNullOrWhiteSpace(signatureRecord.SigningCertificateThumbprint))
			{
				throw new InvalidDataException("Trust signature does not declare a signing certificate thumbprint.");
			}

			byte[] storedSignatureBytes;

			try
			{
				storedSignatureBytes = Convert.FromBase64String(signatureRecord.Signature);
			}
			catch (FormatException ex)
			{
				throw new InvalidDataException("Trust signature stream contains invalid base64 content.", ex);
			}

			var trustedCertificate = LoadTrustedVerificationCertificateOrThrow(signatureRecord.SigningCertificateThumbprint);
			var trustBytes = File.ReadAllBytes(trustPath);
			var isValid = VerifySignature(trustBytes, storedSignatureBytes, trustedCertificate);

			if (!isValid)
			{
				throw new InvalidDataException("Trust store signature validation failed.");
			}
		}

		/// <summary>
		/// Gets the sidecar signature metadata path for a trust store file.
		/// </summary>
		/// <param name="trustPath">Path to the trust store file.</param>
		/// <returns>Path of the signature sidecar file.</returns>
		private string GetSignatureStreamPath(string trustPath)
		{
			return string.Concat(trustPath, ".signature");
		}

		/// <summary>
		/// Attempts to read signature metadata for a trust store file.
		/// </summary>
		/// <param name="trustPath">Path to the trust store file.</param>
		/// <param name="signatureRecord">Deserialized signature metadata when available.</param>
		/// <returns><see langword="true"/> when metadata exists and is deserialized; otherwise <see langword="false"/>.</returns>
		private bool TryReadSignatureRecord(string trustPath, out TrustSignatureRecord signatureRecord)
		{
			signatureRecord = null!;
			var signaturePath = GetSignatureStreamPath(trustPath);

			try
			{
				if (File.Exists(signaturePath))
				{
					var signaturePayload = File.ReadAllText(signaturePath);

					signatureRecord = JsonSerializer.Deserialize<TrustSignatureRecord>(signaturePayload)
						?? throw new InvalidDataException("Unable to deserialize trust signature stream content.");

					return true;
				}
			}
			catch
			{
			}

			return false;
		}

		/// <summary>
		/// Resolves the certificate thumbprint used for signing operations.
		/// </summary>
		/// <param name="providedThumbprint">Caller-supplied thumbprint override.</param>
		/// <returns>Normalized certificate thumbprint.</returns>
		private string ResolveSigningCertificateThumbprint(string? providedThumbprint)
		{
			var thumbprint = string.IsNullOrWhiteSpace(providedThumbprint)
				? Environment.GetEnvironmentVariable("MSBUILDGUARD_POLICY_SIGNING_CERT_THUMBPRINT") ?? string.Empty
				: providedThumbprint;

			if (string.IsNullOrWhiteSpace(thumbprint))
			{
				throw new InvalidOperationException("Signing certificate thumbprint is required.");
			}

			return thumbprint.Replace(" ", string.Empty).ToUpperInvariant();
		}

		/// <summary>
		/// Loads a signing certificate with private key by thumbprint.
		/// </summary>
		/// <param name="thumbprint">Certificate thumbprint.</param>
		/// <returns>The matching certificate containing a private key.</returns>
		private X509Certificate2 LoadSigningCertificateOrThrow(string thumbprint)
		{
			using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

			store.Open(OpenFlags.ReadOnly);

			var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

			if (matches.Count > 0 && matches[0].HasPrivateKey)
			{
				return matches[0];
			}

			using var storeMachine = new X509Store(StoreName.My, StoreLocation.LocalMachine);

			storeMachine.Open(OpenFlags.ReadOnly);

			var matchesMachine = storeMachine.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

			if (matchesMachine.Count > 0 && matchesMachine[0].HasPrivateKey)
			{
				return matchesMachine[0];
			}

			throw new InvalidOperationException($"Signing certificate '{thumbprint}' was not found with private key.");
		}

		/// <summary>
		/// Loads a trusted verification certificate by thumbprint, including optional root CA pin validation.
		/// </summary>
		/// <param name="thumbprint">Certificate thumbprint.</param>
		/// <returns>The matching verification certificate.</returns>
		private X509Certificate2 LoadTrustedVerificationCertificateOrThrow(string thumbprint)
		{
			using var store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);

			store.Open(OpenFlags.ReadOnly);

			var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

			if (matches.Count > 0)
			{
				// Optional Root CA Pinning verification
				var pinnedCa = Environment.GetEnvironmentVariable("MSBUILDGUARD_ROOT_CA_THUMBPRINT");

				if (!string.IsNullOrWhiteSpace(pinnedCa))
				{
					var normalizedPinnedCa = pinnedCa!.Replace(" ", string.Empty).ToUpperInvariant();
					var chain = new X509Chain();

					chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
					chain.Build(matches[0]);

					var isChainValid = false;

					foreach (var element in chain.ChainElements)
					{
						var elementThumb = element.Certificate.Thumbprint.Replace(" ", string.Empty).ToUpperInvariant();

						if (string.Equals(elementThumb, normalizedPinnedCa, StringComparison.OrdinalIgnoreCase))
						{
							isChainValid = true;

							break;
						}
					}

					if (!isChainValid)
					{
						throw new InvalidDataException($"The verification certificate is not issued by the trusted Root CA '{normalizedPinnedCa}'.");
					}
				}

				return matches[0];
			}

			var allowCurrentUser = Environment.GetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE");

			if (string.Equals(allowCurrentUser, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(allowCurrentUser, "1"))
			{
				using var storeUser = new X509Store(StoreName.TrustedPeople, StoreLocation.CurrentUser);

				storeUser.Open(OpenFlags.ReadOnly);

				var matchesUser = storeUser.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

				if (matchesUser.Count > 0)
				{
					return matchesUser[0];
				}
			}

			throw new InvalidDataException($"Trusted verification certificate '{thumbprint}' was not found.");
		}

		/// <summary>
		/// Computes an RSA PKCS#1 v1.5 SHA-256 signature over the supplied payload.
		/// </summary>
		/// <param name="payload">Payload bytes to sign.</param>
		/// <param name="certificate">Certificate containing the signing private key.</param>
		/// <returns>Signature bytes.</returns>
		private static byte[] ComputeSignature(byte[] payload, X509Certificate2 certificate)
		{
			using var rsa = certificate.GetRSAPrivateKey();

			if (rsa == null)
			{
				throw new InvalidOperationException("Certificate does not provide an RSA private key.");
			}

			return rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		}

		/// <summary>
		/// Verifies an RSA PKCS#1 v1.5 SHA-256 signature.
		/// </summary>
		/// <param name="payload">Original payload bytes.</param>
		/// <param name="signature">Signature bytes.</param>
		/// <param name="certificate">Certificate containing the verification public key.</param>
		/// <returns><see langword="true"/> when the signature is valid; otherwise <see langword="false"/>.</returns>
		private static bool VerifySignature(byte[] payload, byte[] signature, X509Certificate2 certificate)
		{
			using var rsa = certificate.GetRSAPublicKey();

			if (rsa == null)
			{
				throw new InvalidDataException("Certificate does not provide an RSA public key.");
			}

			return rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		}

		/// <summary>
		/// Gets or creates the local DPAPI-protected symmetric key used for trust-store envelope signing.
		/// </summary>
		/// <returns>Base64 key material, or fallback static key when key access fails.</returns>
		private string GetLocalDPAPIKey()
		{
			var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
			var keyDir = Path.Combine(appData, "MSBuildGuard");
			var keyPath = Path.Combine(keyDir, "machine.key");

			try
			{
				if (!Directory.Exists(keyDir))
				{
					Directory.CreateDirectory(keyDir);
				}

				if (File.Exists(keyPath))
				{
					var encrypted = File.ReadAllBytes(keyPath);
					var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);

					return Encoding.UTF8.GetString(decrypted);
				}
				else
				{
					var keyBytes = new byte[32];

					using (var rng = RandomNumberGenerator.Create())
					{
						rng.GetBytes(keyBytes);
					}

					var keyString = Convert.ToBase64String(keyBytes);
					var rawKeyBytes = Encoding.UTF8.GetBytes(keyString);
					var encrypted = ProtectedData.Protect(rawKeyBytes, null, DataProtectionScope.CurrentUser);

					File.WriteAllBytes(keyPath, encrypted);

					return keyString;
				}
			}
			catch (Exception)
			{
				return GetLocalUnprotectedKey(keyDir);
			}
		}

		/// <summary>
		/// Gets or creates a local unprotected symmetric key used when DPAPI is unavailable.
		/// </summary>
		/// <param name="keyDir">The key directory path.</param>
		/// <returns>Base64 key material, or fallback static key if file operations fail.</returns>
		private string GetLocalUnprotectedKey(string keyDir)
		{
			try
			{
				var unprotectedKeyPath = Path.Combine(keyDir, "machine.key.fallback");

				if (!Directory.Exists(keyDir))
				{
					Directory.CreateDirectory(keyDir);
				}

				if (File.Exists(unprotectedKeyPath))
				{
					return File.ReadAllText(unprotectedKeyPath);
				}
				else
				{
					var keyBytes = new byte[32];

					using (var rng = RandomNumberGenerator.Create())
					{
						rng.GetBytes(keyBytes);
					}

					var keyString = Convert.ToBase64String(keyBytes);

					File.WriteAllText(unprotectedKeyPath, keyString);

					return keyString;
				}
			}
			catch (Exception)
			{
				return TrustStoreSigningKey;
			}
		}

		/// <summary>
		/// Determines whether a trust-store path corresponds to the default user-level trust store.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <returns><see langword="true"/> when the path is the default user trust store path; otherwise <see langword="false"/>.</returns>
		private bool IsUserTrustPath(string path)
		{
			try
			{
				var userDefaultPath = GetDefaultUserTrustPath();

				return string.Equals(Path.GetFullPath(path), Path.GetFullPath(userDefaultPath), StringComparison.OrdinalIgnoreCase);
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		/// Resolves the symmetric signing key for a trust-store path.
		/// </summary>
		/// <param name="path">Trust store path.</param>
		/// <returns>Resolved signing key.</returns>
		private string GetSigningKeyForPath(string path)
		{
			if (IsUserTrustPath(path))
			{
				return GetLocalDPAPIKey();
			}

			if (CoreSettings.AllowSharingTrustsInRepositories)
			{
				return TrustStoreSigningKey;
			}

			return GetLocalDPAPIKey();
		}

		/// <summary>
		/// Pins a repository directory so future trust loads require asymmetric signatures.
		/// </summary>
		/// <param name="path">Trust store path used to determine repository directory.</param>
		private void PinRepositoryAsAsymmetricRequired(string path)
		{
			try
			{
				var solutionDir = Path.GetDirectoryName(path);

				if (string.IsNullOrWhiteSpace(solutionDir))
				{
					return;
				}

				if (string.Equals(Path.GetFileName(solutionDir), ".msbuildguard", StringComparison.OrdinalIgnoreCase))
				{
					solutionDir = Path.GetDirectoryName(solutionDir);
				}

				if (string.IsNullOrWhiteSpace(solutionDir))
				{
					return;
				}

				var pinned = LoadPinnedRepositories();

				if (!pinned.Contains(solutionDir, StringComparer.OrdinalIgnoreCase))
				{
					pinned.Add(solutionDir);
					SavePinnedRepositories(pinned);
				}
			}
			catch
			{
			}
		}

		/// <summary>
		/// Determines whether a repository directory is pinned to require asymmetric trust signatures.
		/// </summary>
		/// <param name="path">Trust store path used to determine repository directory.</param>
		/// <returns><see langword="true"/> when the repository is pinned; otherwise <see langword="false"/>.</returns>
		private bool IsRepositoryPinnedAsAsymmetricRequired(string path)
		{
			try
			{
				var solutionDir = Path.GetDirectoryName(path);

				if (string.IsNullOrWhiteSpace(solutionDir))
				{
					return false;
				}

				if (string.Equals(Path.GetFileName(solutionDir), ".msbuildguard", StringComparison.OrdinalIgnoreCase))
				{
					solutionDir = Path.GetDirectoryName(solutionDir);
				}

				if (string.IsNullOrWhiteSpace(solutionDir))
				{
					return false;
				}

				var pinned = LoadPinnedRepositories();

				return pinned.Contains(solutionDir, StringComparer.OrdinalIgnoreCase);
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		/// Loads the persisted list of repositories pinned for asymmetric-signature enforcement.
		/// </summary>
		/// <returns>List of pinned repository directories.</returns>
		private List<string> LoadPinnedRepositories()
		{
			try
			{
				var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
				var pinPath = Path.Combine(appData, "MSBuildGuard", "pinned.bson");

				if (File.Exists(pinPath))
				{
					var encrypted = File.ReadAllBytes(pinPath);
					var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
					var json = Encoding.UTF8.GetString(decrypted);

					return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
				}
			}
			catch
			{
			}

			return new List<string>();
		}

		/// <summary>
		/// Persists the list of repositories pinned for asymmetric-signature enforcement.
		/// </summary>
		/// <param name="pinned">Pinned repository directories.</param>
		private void SavePinnedRepositories(List<string> pinned)
		{
			try
			{
				var json = JsonSerializer.Serialize(pinned);
				var rawBytes = Encoding.UTF8.GetBytes(json);
				var encrypted = ProtectedData.Protect(rawBytes, null, DataProtectionScope.CurrentUser);

				var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
				var pinPath = Path.Combine(appData, "MSBuildGuard", "pinned.bson");

				File.WriteAllBytes(pinPath, encrypted);
			}
			catch
			{
			}
		}
	}
}


