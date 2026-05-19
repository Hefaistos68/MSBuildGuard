using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using System.Text.Json;
using MSBuildGuard.Core.Baseline;

namespace MSBuildGuard.Core.Policy
{
	/// <summary>
	/// Provides policy loading, persistence, and precedence merging.
	/// </summary>
	public sealed class PolicyService
	{
		/// <summary>
		/// Defines the current policy signature stream format version.
		/// </summary>
		private const int PolicySignatureVersion = 1;

		/// <summary>
		/// Defines the signature algorithm used for policy signing.
		/// </summary>
		private const string PolicySignatureAlgorithm = "RSASSA-PKCS1-v1_5-SHA256";

		/// <summary>
		/// Defines the alternate data stream name used to store policy signatures.
		/// </summary>
		private const string PolicySignatureStreamName = "msbuildguard.policy.signature";

		/// <summary>
		/// Defines the environment variable name for the signing certificate thumbprint.
		/// </summary>
		private const string SigningThumbprintVariable = "MSBUILDGUARD_POLICY_SIGNING_CERT_THUMBPRINT";

		/// <summary>
		/// Defines the environment variable that enables CurrentUser trusted store fallback.
		/// </summary>
		private const string AllowCurrentUserTrustedStoreVariable = "MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE";

		/// <summary>
		/// Defines the symmetric signing key used for signed policy envelopes.
		/// </summary>
		private const string PolicyEnvelopeSigningKey = "8d4f04ae-38d2-4f89-a5f2-425af9ca40ef";

		/// <summary>
		/// Provides serializer options for policy document persistence.
		/// </summary>
		private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
		{
			WriteIndented = true
		};

		/// <summary>
		/// Provides serializer options for policy signature payload persistence.
		/// </summary>
		private static readonly JsonSerializerOptions SignatureSerializerOptions = new JsonSerializerOptions
		{
			WriteIndented = true
		};

		/// <summary>
		/// Represents the persisted policy signature metadata.
		/// </summary>
		private sealed class PolicySignatureRecord
		{
			/// <summary>
			/// Gets or sets the signature payload version.
			/// </summary>
			public int Version { get; set; } = PolicySignatureVersion;

			/// <summary>
			/// Gets or sets the signature algorithm identifier.
			/// </summary>
			public string Algorithm { get; set; } = PolicySignatureAlgorithm;

			/// <summary>
			/// Gets or sets the signer certificate thumbprint.
			/// </summary>
			public string SigningCertificateThumbprint { get; set; } = string.Empty;

			/// <summary>
			/// Gets or sets the base64-encoded signature value.
			/// </summary>
			public string Signature { get; set; } = string.Empty;
		}

		/// <summary>
		/// Creates default policy values.
		/// </summary>
		/// <returns>A new default policy document.</returns>
		public PolicyDocument CreateDefault()
		{
			var policy = new PolicyDocument
			{
				BaselineRequired = false,
				IncompleteAnalysisAction = PolicyAction.Warn,
				Mode             = "warn",
				StrictMode       = false,
				UnapprovedPackageSourceAction = PolicyAction.RequireApproval,
				Version          = 1
			};

			policy.MinimumActionBySeverity[FindingSeverity.Critical] = PolicyAction.Block;
			policy.MinimumActionBySeverity[FindingSeverity.High] = PolicyAction.Block;
			policy.MinimumActionBySeverity[FindingSeverity.Medium] = PolicyAction.RequireApproval;
			policy.MinimumActionBySeverity[FindingSeverity.Low] = PolicyAction.Warn;
			policy.MinimumActionBySeverity[FindingSeverity.Info] = PolicyAction.Allow;

			return policy;
		}

		/// <summary>
		/// Saves policy content to disk.
		/// </summary>
		/// <param name="path">The policy file path.</param>
		/// <param name="policy">The policy to save.</param>
		public void Save(string path, PolicyDocument policy)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			if (policy == null)
			{
				throw new ArgumentNullException(nameof(policy));
			}

			var directory = Path.GetDirectoryName(path);

			if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
			{
				Directory.CreateDirectory(directory);
			}

			var json = JsonSerializer.Serialize(policy, SerializerOptions);
			var signedPayload = new JsonSignatureService().CreateSignedEnvelopeJson(json, PolicyEnvelopeSigningKey);

			File.WriteAllText(path, signedPayload);
		}

		/// <summary>
		/// Loads policy content from disk.
		/// </summary>
		/// <param name="path">The policy file path.</param>
		/// <returns>The loaded policy document.</returns>
		public PolicyDocument? Load(string path)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			// check first if the file exists
			if (!File.Exists(path))
			{
				return null;
			}

			var payload = File.ReadAllText(path);
			var signatureService = new JsonSignatureService();

			if (!signatureService.TryVerifyAndExtract<string>(payload, PolicyEnvelopeSigningKey, out var policyPayload) || string.IsNullOrWhiteSpace(policyPayload))
			{
				throw new InvalidDataException("Policy signature validation failed. Run 'msbuildguard policy sign <policyPath>' after legitimate edits.");
			}

			ValidateSignedPolicy(path);

			var policy = JsonSerializer.Deserialize<PolicyDocument>(policyPayload!, SerializerOptions);

			if (policy == null)
			{
				throw new InvalidDataException("Unable to deserialize policy file.");
			}

			return policy;
		}

		/// <summary>
		/// Loads policy content from disk without verifying the signature.
		/// Intended for editor scenarios where the file may not yet be signed.
		/// </summary>
		/// <param name="path">The policy file path.</param>
		/// <returns>The loaded policy document.</returns>
		public PolicyDocument LoadUnsigned(string path)
		{
			if (path == null)
			{
				throw new ArgumentNullException(nameof(path));
			}

			var payload = File.ReadAllText(path);
			var signatureService = new JsonSignatureService();

			if (!signatureService.TryVerifyAndExtract<string>(payload, PolicyEnvelopeSigningKey, out var policyPayload) || string.IsNullOrWhiteSpace(policyPayload))
			{
				throw new InvalidDataException("Unable to deserialize policy file.");
			}

			var policy = JsonSerializer.Deserialize<PolicyDocument>(policyPayload!, SerializerOptions);

			if (policy == null)
			{
				throw new InvalidDataException("Unable to deserialize policy file.");
			}

			return policy;
		}


		/// <summary>
		/// Signs a policy file and stores the signature in an NTFS alternate data stream.
		/// </summary>
		/// <param name="policyPath">The policy file path.</param>
		/// <param name="signingCertificateThumbprint">Optional signing certificate thumbprint.</param>
		public void Sign(string policyPath, string? signingCertificateThumbprint)
		{
			if (policyPath == null)
			{
				throw new ArgumentNullException(nameof(policyPath));
			}

			if (!File.Exists(policyPath))
			{
				throw new FileNotFoundException("Policy file was not found.", policyPath);
			}

			var thumbprint = ResolveSigningCertificateThumbprint(signingCertificateThumbprint);
			var certificate = LoadSigningCertificateOrThrow(thumbprint);

			var policyBytes = File.ReadAllBytes(policyPath);
			var signatureBytes = ComputeSignature(policyBytes, certificate);
			var signatureRecord = new PolicySignatureRecord
			{
				Version = PolicySignatureVersion,
				Algorithm = PolicySignatureAlgorithm,
				SigningCertificateThumbprint = thumbprint,
				Signature = Convert.ToBase64String(signatureBytes)
			};
			var signaturePath = GetSignatureStreamPath(policyPath);
			var payload = JsonSerializer.Serialize(signatureRecord, SignatureSerializerOptions);

			WriteAllText(signaturePath, payload);
		}

		/// <summary>
		/// Validates policy file signature and throws on any validation failure.
		/// </summary>
		/// <param name="policyPath">The policy file path.</param>
		public void ValidateSignedPolicy(string policyPath)
		{
			if (policyPath == null)
			{
				throw new ArgumentNullException(nameof(policyPath));
			}

			if (!File.Exists(policyPath))
			{
				throw new FileNotFoundException("Policy file was not found.", policyPath);
			}

			if (!TryReadSignatureRecord(policyPath, out var signatureRecord))
			{
				return;
			}

			if (signatureRecord.Version != PolicySignatureVersion)
			{
				throw new InvalidDataException($"Policy signature stream uses unsupported version '{signatureRecord.Version}'.");
			}

			if (!string.Equals(signatureRecord.Algorithm, PolicySignatureAlgorithm, StringComparison.OrdinalIgnoreCase))
			{
				throw new InvalidDataException($"Policy signature stream uses unsupported algorithm '{signatureRecord.Algorithm}'.");
			}

			if (string.IsNullOrWhiteSpace(signatureRecord.Signature))
			{
				throw new InvalidDataException("Policy signature is missing. Run 'msbuildguard policy sign <policyPath>' after editing the policy.");
			}

			if (string.IsNullOrWhiteSpace(signatureRecord.SigningCertificateThumbprint))
			{
				throw new InvalidDataException("Policy signature does not declare a signing certificate thumbprint.");
			}

			byte[] storedSignatureBytes;

			try
			{
				storedSignatureBytes = Convert.FromBase64String(signatureRecord.Signature);
			}
			catch (FormatException ex)
			{
				throw new InvalidDataException("Policy signature stream contains invalid base64 content.", ex);
			}

			var trustedCertificate = LoadTrustedVerificationCertificateOrThrow(signatureRecord.SigningCertificateThumbprint);
			var policyBytes = File.ReadAllBytes(policyPath);
			var isValid = VerifySignature(policyBytes, storedSignatureBytes, trustedCertificate);

			if (!isValid)
			{
				throw new InvalidDataException("Policy signature validation failed. Run 'msbuildguard policy sign <policyPath>' after legitimate edits.");
			}
		}

		/// <summary>
		/// Validates policy file signature and returns validation status.
		/// </summary>
		/// <param name="policyPath">The policy file path.</param>
		/// <param name="validationMessage">Validation details.</param>
		/// <returns><see langword="true"/> when policy signature is valid; otherwise <see langword="false"/>.</returns>
		public bool TryValidateSignature(string policyPath, out string validationMessage)
		{
			if (policyPath == null)
			{
				throw new ArgumentNullException(nameof(policyPath));
			}

			try
			{
				ValidateSignedPolicy(policyPath);

				validationMessage = HasSignatureStream(policyPath)
					? "Policy signature is valid."
					: "Policy JSON content is valid. No external policy signature was found.";

				return true;
			}
			catch (Exception ex) when (ex is InvalidDataException || ex is InvalidOperationException || ex is IOException || ex is UnauthorizedAccessException || ex is PlatformNotSupportedException)
			{
				validationMessage = ex.Message;

				return false;
			}
		}

		/// <summary>
		/// Gets the signature stream path for a policy file.
		/// </summary>
		/// <param name="policyPath">The policy file path.</param>
		/// <returns>The signature stream path.</returns>
		public string GetSignatureStreamPath(string policyPath)
		{
			if (policyPath == null)
			{
				throw new ArgumentNullException(nameof(policyPath));
			}

			return string.Concat(policyPath, ":", PolicySignatureStreamName);
		}

		/// <summary>
		/// Gets the configured policy signing certificate thumbprint from environment.
		/// </summary>
		/// <returns>The configured thumbprint or empty string.</returns>
		public string GetConfiguredSigningCertificateThumbprint()
		{
			return Environment.GetEnvironmentVariable(SigningThumbprintVariable) ?? string.Empty;
		}

		/// <summary>
		/// Merges policies by precedence: machine, repository, user, defaults.
		/// </summary>
		/// <param name="machine">Machine policy.</param>
		/// <param name="repository">Repository policy.</param>
		/// <param name="user">User policy.</param>
		/// <param name="defaults">Built-in defaults.</param>
		/// <returns>Merged effective policy.</returns>
		public PolicyDocument Merge(PolicyDocument? machine, PolicyDocument? repository, PolicyDocument? user, PolicyDocument defaults)
		{
			if (defaults == null)
			{
				throw new ArgumentNullException(nameof(defaults));
			}

			var effective = Clone(defaults);

			ApplyLayer(effective, user);
			ApplyLayer(effective, repository);
			ApplyLayer(effective, machine);

			return effective;
		}

		/// <summary>
		/// Applies a policy layer onto a target policy document.
		/// </summary>
		/// <param name="target">The target policy receiving values.</param>
		/// <param name="source">The source policy layer to apply.</param>
		private static void ApplyLayer(PolicyDocument target, PolicyDocument? source)
		{
			if (target == null)
			{
				throw new ArgumentNullException(nameof(target));
			}

			if (source == null)
			{
				return;
			}

			target.Version = source.Version;
			target.Mode = source.Mode;
			target.BaselineRequired = source.BaselineRequired;
			target.StrictMode = source.StrictMode;
			target.IncompleteAnalysisAction = source.IncompleteAnalysisAction;
			target.UnapprovedPackageSourceAction = source.UnapprovedPackageSourceAction;

			foreach (var pair in source.MinimumActionBySeverity)
			{
				target.MinimumActionBySeverity[pair.Key] = pair.Value;
			}

			foreach (var pair in source.Rules)
			{
				target.Rules[pair.Key] = new PolicyRuleSetting
				{
					Action = pair.Value.Action
				};
			}

			target.Include.Clear();

			foreach (var pattern in source.Include)
			{
				target.Include.Add(pattern);
			}

			target.Exclude.Clear();

			foreach (var pattern in source.Exclude)
			{
				target.Exclude.Add(pattern);
			}

			target.AllowedPackageSources.Clear();

			foreach (var packageSource in source.AllowedPackageSources)
			{
				target.AllowedPackageSources.Add(packageSource);
			}

			target.BlockedPackageSources.Clear();

			foreach (var packageSource in source.BlockedPackageSources)
			{
				target.BlockedPackageSources.Add(packageSource);
			}
		}

		/// <summary>
		/// Creates a deep clone of a policy document.
		/// </summary>
		/// <param name="source">The source policy document.</param>
		/// <returns>A cloned policy document.</returns>
		private static PolicyDocument Clone(PolicyDocument source)
		{
			var clone = new PolicyDocument
			{
				BaselineRequired = source.BaselineRequired,
				IncompleteAnalysisAction = source.IncompleteAnalysisAction,
				Mode             = source.Mode,
				StrictMode       = source.StrictMode,
				UnapprovedPackageSourceAction = source.UnapprovedPackageSourceAction,
				Version          = source.Version
			};

			foreach (var pair in source.MinimumActionBySeverity)
			{
				clone.MinimumActionBySeverity[pair.Key] = pair.Value;
			}

			foreach (var pair in source.Rules)
			{
				clone.Rules[pair.Key] = new PolicyRuleSetting
				{
					Action = pair.Value.Action
				};
			}

			foreach (var pattern in source.Include)
			{
				clone.Include.Add(pattern);
			}

			foreach (var pattern in source.Exclude)
			{
				clone.Exclude.Add(pattern);
			}

			foreach (var packageSource in source.AllowedPackageSources)
			{
				clone.AllowedPackageSources.Add(packageSource);
			}

			foreach (var packageSource in source.BlockedPackageSources)
			{
				clone.BlockedPackageSources.Add(packageSource);
			}

			return clone;
		}

		/// <summary>
		/// Computes effective policy action for a finding.
		/// </summary>
		/// <param name="policy">The effective policy.</param>
		/// <param name="finding">The finding to evaluate.</param>
		/// <returns>The policy action.</returns>
		public PolicyAction ResolveAction(PolicyDocument policy, Finding finding)
		{
			if (policy == null)
			{
				throw new ArgumentNullException(nameof(policy));
			}

			if (finding == null)
			{
				throw new ArgumentNullException(nameof(finding));
			}

			if (policy.Rules.TryGetValue(finding.Id, out var ruleOverride))
			{
				return ruleOverride.Action;
			}

			if (string.Equals(finding.Id, "MBG012", StringComparison.OrdinalIgnoreCase))
			{
				return policy.StrictMode ? MaxAction(policy.IncompleteAnalysisAction, PolicyAction.Block) : MaxAction(policy.IncompleteAnalysisAction, finding.PolicyAction);
			}

			if (policy.MinimumActionBySeverity.TryGetValue(finding.Severity, out var action))
			{
				return action;
			}

			return finding.PolicyAction;
		}

		/// <summary>
		/// Returns the stricter of two policy actions.
		/// </summary>
		/// <param name="left">The first action.</param>
		/// <param name="right">The second action.</param>
		/// <returns>The stricter action.</returns>
		private static PolicyAction MaxAction(PolicyAction left, PolicyAction right)
		{
			return (PolicyAction)Math.Max((int)left, (int)right);
		}

		/// <summary>
		/// Resolves the effective signing certificate thumbprint from arguments or environment.
		/// </summary>
		/// <param name="providedThumbprint">The optional thumbprint provided by caller.</param>
		/// <returns>The normalized thumbprint.</returns>
		private string ResolveSigningCertificateThumbprint(string? providedThumbprint)
		{
			var thumbprint = string.IsNullOrWhiteSpace(providedThumbprint)
				? GetConfiguredSigningCertificateThumbprint()
				: providedThumbprint;

			if (string.IsNullOrWhiteSpace(thumbprint))
			{
				throw new InvalidOperationException($"Signing certificate thumbprint is required. Pass --thumbprint <hex> or set {SigningThumbprintVariable}.");
			}

			var resolvedThumbprint = thumbprint!;

			return NormalizeThumbprint(resolvedThumbprint);
		}

		/// <summary>
		/// Loads the signing certificate including private key from available certificate stores.
		/// </summary>
		/// <param name="thumbprint">The certificate thumbprint.</param>
		/// <returns>The signing certificate.</returns>
		private X509Certificate2 LoadSigningCertificateOrThrow(string thumbprint)
		{
			var certificate = TryFindCertificate(StoreName.My, StoreLocation.CurrentUser, thumbprint)
				?? TryFindCertificate(StoreName.My, StoreLocation.LocalMachine, thumbprint);

			if (certificate == null)
			{
				throw new InvalidOperationException($"Signing certificate '{thumbprint}' was not found in CurrentUser/My or LocalMachine/My.");
			}

			if (!certificate.HasPrivateKey)
			{
				throw new InvalidOperationException($"Signing certificate '{thumbprint}' does not have an accessible private key.");
			}

			return certificate;
		}

		/// <summary>
		/// Loads a trusted verification certificate from trusted people stores.
		/// </summary>
		/// <param name="thumbprint">The certificate thumbprint.</param>
		/// <returns>The trusted verification certificate.</returns>
		private X509Certificate2 LoadTrustedVerificationCertificateOrThrow(string thumbprint)
		{
			var normalized = NormalizeThumbprint(thumbprint);
			var certificate = TryFindCertificate(StoreName.TrustedPeople, StoreLocation.LocalMachine, normalized);

			if (certificate != null)
			{
				return certificate;
			}

			if (AllowCurrentUserTrustedStore())
			{
				certificate = TryFindCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, normalized);

				if (certificate != null)
				{
					return certificate;
				}
			}

			throw new InvalidDataException($"Trusted verification certificate '{normalized}' was not found in LocalMachine/TrustedPeople. Import signer public certificate there. For test/dev only, set {AllowCurrentUserTrustedStoreVariable}=true to allow CurrentUser/TrustedPeople fallback.");
		}

		/// <summary>
		/// Attempts to find a certificate by thumbprint in the specified store.
		/// </summary>
		/// <param name="storeName">The certificate store name.</param>
		/// <param name="storeLocation">The certificate store location.</param>
		/// <param name="thumbprint">The certificate thumbprint.</param>
		/// <returns>The matching certificate, or <see langword="null"/> when no match exists.</returns>
		private static X509Certificate2? TryFindCertificate(StoreName storeName, StoreLocation storeLocation, string thumbprint)
		{
			var normalized = NormalizeThumbprint(thumbprint);

			using var store = new X509Store(storeName, storeLocation);

			store.Open(OpenFlags.ReadOnly);

			var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, false);

			if (matches.Count == 0)
			{
				return null;
			}

			return matches[0];
		}

		/// <summary>
		/// Normalizes a thumbprint value for comparison and lookup.
		/// </summary>
		/// <param name="thumbprint">The thumbprint to normalize.</param>
		/// <returns>The normalized thumbprint.</returns>
		private static string NormalizeThumbprint(string thumbprint)
		{
			return thumbprint.Replace(" ", string.Empty).ToUpperInvariant();
		}

		/// <summary>
		/// Determines whether CurrentUser trusted store fallback is enabled.
		/// </summary>
		/// <returns><see langword="true"/> when fallback is enabled; otherwise <see langword="false"/>.</returns>
		private static bool AllowCurrentUserTrustedStore()
		{
			var raw = Environment.GetEnvironmentVariable(AllowCurrentUserTrustedStoreVariable);

			if (string.IsNullOrWhiteSpace(raw))
			{
				return false;
			}

			return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);
		}

		/// <summary>
		/// Computes the signature for a payload using the provided signing certificate.
		/// </summary>
		/// <param name="payload">The payload bytes to sign.</param>
		/// <param name="certificate">The signing certificate.</param>
		/// <returns>The computed signature bytes.</returns>
		private static byte[] ComputeSignature(byte[] payload, X509Certificate2 certificate)
		{
			using var rsa = certificate.GetRSAPrivateKey();

			if (rsa == null)
			{
				throw new InvalidOperationException($"Signing certificate '{certificate.Thumbprint}' does not provide an RSA private key.");
			}

			return rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		}

		/// <summary>
		/// Verifies a payload signature using the provided verification certificate.
		/// </summary>
		/// <param name="payload">The original payload bytes.</param>
		/// <param name="signature">The signature bytes.</param>
		/// <param name="certificate">The verification certificate.</param>
		/// <returns><see langword="true"/> when the signature is valid; otherwise <see langword="false"/>.</returns>
		private static bool VerifySignature(byte[] payload, byte[] signature, X509Certificate2 certificate)
		{
			using var rsa = certificate.GetRSAPublicKey();

			if (rsa == null)
			{
				throw new InvalidDataException($"Trusted verification certificate '{certificate.Thumbprint}' does not provide an RSA public key.");
			}

			return rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		}

		/// <summary>
		/// Reads and deserializes the policy signature record from the signature stream.
		/// </summary>
		/// <param name="policyPath">The policy file path.</param>
		/// <returns>The deserialized policy signature record.</returns>
		private PolicySignatureRecord ReadSignatureRecord(string policyPath)
		{
			var signaturePath = GetSignatureStreamPath(policyPath);
			string signaturePayload;

			try
			{
				signaturePayload = File.ReadAllText(signaturePath);
			}
			catch (FileNotFoundException ex)
			{
				throw new InvalidDataException("Policy signature stream is missing. The policy may have been copied to a file system that strips alternate data streams (for example non-NTFS) or edited without re-signing. Run 'msbuildguard policy sign <policyPath>' after legitimate edits.", ex);
			}
			catch (DirectoryNotFoundException ex)
			{
				throw new InvalidDataException("Policy signature stream is missing. The policy may have been copied to a file system that strips alternate data streams (for example non-NTFS) or edited without re-signing. Run 'msbuildguard policy sign <policyPath>' after legitimate edits.", ex);
			}
			catch (NotSupportedException ex)
			{
				throw new InvalidDataException("Policy signature stream is not supported on this file system. Use NTFS policy paths.", ex);
			}

			var signatureRecord = JsonSerializer.Deserialize<PolicySignatureRecord>(signaturePayload, SignatureSerializerOptions);

			if (signatureRecord == null)
			{
				throw new InvalidDataException("Unable to deserialize policy signature stream content.");
			}

			return signatureRecord;
		}

		/// <summary>
		/// Attempts to read the policy signature record when an external signature stream exists.
		/// </summary>
		/// <param name="policyPath">The policy file path.</param>
		/// <param name="signatureRecord">The deserialized signature record when available.</param>
		/// <returns><see langword="true"/> when an external signature record exists; otherwise <see langword="false"/>.</returns>
		private bool TryReadSignatureRecord(string policyPath, out PolicySignatureRecord signatureRecord)
		{
			signatureRecord = null!;
			var signaturePath = GetSignatureStreamPath(policyPath);
			string signaturePayload;
			
			try
			{
				signaturePayload = File.ReadAllText(signaturePath);
			}
			catch (FileNotFoundException)
			{
				return false;
			}
			catch (DirectoryNotFoundException)
			{
				return false;
			}
			catch (NotSupportedException)
			{
				return false;
			}

			signatureRecord = JsonSerializer.Deserialize<PolicySignatureRecord>(signaturePayload, SignatureSerializerOptions)
				?? throw new InvalidDataException("Unable to deserialize policy signature stream content.");

			return true;
		}

		/// <summary>
		/// Determines whether a signature stream currently exists for the specified policy path.
		/// </summary>
		/// <param name="policyPath">The policy file path.</param>
		/// <returns><see langword="true"/> when the signature stream exists; otherwise <see langword="false"/>.</returns>
		private bool HasSignatureStream(string policyPath)
		{
			return TryReadSignatureRecord(policyPath, out _);
		}

		/// <summary>
		/// Validates the signed JSON envelope embedded in the policy file.
		/// </summary>
		/// <param name="policyPath">The policy file path.</param>
		private void ValidatePolicyEnvelopeOrThrow(string policyPath)
		{
			var payload = File.ReadAllText(policyPath);
			var signatureService = new JsonSignatureService();

			if (!signatureService.TryVerifyAndExtract<string>(payload, PolicyEnvelopeSigningKey, out var policyPayload) || string.IsNullOrWhiteSpace(policyPayload))
			{
				throw new InvalidDataException("Policy JSON content validation failed. Run 'msbuildguard policy sign <policyPath>' after legitimate edits.");
			}
		}

		/// <summary>
		/// Writes text content to a file path and creates parent directory when needed.
		/// </summary>
		/// <param name="path">The target file path.</param>
		/// <param name="content">The text content to write.</param>
		private static void WriteAllText(string path, string content)
		{
			var directory = Path.GetDirectoryName(path);

			if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
			{
				Directory.CreateDirectory(directory);
			}

			File.WriteAllText(path, content);
		}

		/// <summary>
		/// Gets default machine policy path.
		/// </summary>
		/// <returns>Machine policy absolute path.</returns>
		public string GetMachinePolicyPath()
		{
			var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

			return Path.Combine(programData, "MSBuildGuard", "policy.json");
		}

		/// <summary>
		/// Gets default repository policy path.
		/// </summary>
		/// <param name="repositoryRoot">The repository root path.</param>
		/// <returns>Repository policy path.</returns>
		public string GetRepositoryPolicyPath(string repositoryRoot)
		{
			if (repositoryRoot == null)
			{
				throw new ArgumentNullException(nameof(repositoryRoot));
			}

			return Path.Combine(repositoryRoot, ".msbuildguard", "policy.json");
		}

		/// <summary>
		/// Gets default project policy path.
		/// </summary>
		/// <param name="projectPath">The project file path.</param>
		/// <returns>Project policy path.</returns>
		public string GetProjectPolicyPath(string projectPath)
		{
			if (projectPath == null)
			{
				throw new ArgumentNullException(nameof(projectPath));
			}

			var projectDirectory = Path.GetDirectoryName(projectPath);

			if (string.IsNullOrWhiteSpace(projectDirectory))
			{
				throw new ArgumentException("A valid project directory is required.", nameof(projectPath));
			}

			var projectName = Path.GetFileNameWithoutExtension(projectPath);

			if (string.IsNullOrWhiteSpace(projectName))
			{
				projectName = "project";
			}

			var safeProjectName = SanitizeFileNameSegment(projectName);

			return Path.Combine(projectDirectory, ".msbuildguard", $"policy.{safeProjectName}.json");
		}

		private static string SanitizeFileNameSegment(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				return "project";
			}

			var invalidChars = Path.GetInvalidFileNameChars();
			var chars = value.ToCharArray();

			for (var i = 0; i < chars.Length; i++)
			{
				if (invalidChars.Contains(chars[i]))
				{
					chars[i] = '_';
				}
			}

			var sanitized = new string(chars).Trim().Trim('.');

			if (string.IsNullOrWhiteSpace(sanitized))
			{
				return "project";
			}

			return sanitized;
		}

		/// <summary>
		/// Gets default user policy path.
		/// </summary>
		/// <returns>User policy path.</returns>
		public string GetUserPolicyPath()
		{
			var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

			return Path.Combine(localData, "MSBuildGuard", "policy.json");
		}

		/// <summary>
		/// Determines whether a file path should be evaluated based on policy Include/Exclude patterns.
		/// </summary>
		/// <param name="filePath">The file path to check.</param>
		/// <param name="policy">The policy document.</param>
		/// <returns>True if the file should be evaluated; false if it should be excluded.</returns>
		public bool ShouldEvaluateFile(string filePath, PolicyDocument policy)
		{
			if (filePath == null)
			{
				throw new ArgumentNullException(nameof(filePath));
			}

			if (policy == null)
			{
				throw new ArgumentNullException(nameof(policy));
			}

			// If Include patterns are specified, file must match at least one Include pattern
			if (policy.Include.Count > 0)
			{
				if (!MatchesAnyPattern(filePath, policy.Include))
				{
					return false;
				}
			}

			// If Exclude patterns are specified, file must not match any Exclude pattern
			if (policy.Exclude.Count > 0)
			{
				if (MatchesAnyPattern(filePath, policy.Exclude))
				{
					return false;
				}
			}

			return true;
		}

		/// <summary>
		/// Determines whether a file path matches any pattern in the provided list.
		/// </summary>
		/// <param name="filePath">The file path to evaluate.</param>
		/// <param name="patterns">The pattern list to match against.</param>
		/// <returns><see langword="true"/> when any pattern matches; otherwise <see langword="false"/>.</returns>
		private bool MatchesAnyPattern(string filePath, IList<string> patterns)
		{
			if (patterns == null || patterns.Count == 0)
			{
				return false;
			}

			// Normalize path separators for cross-platform consistency
			var normalizedPath = filePath.Replace("\\", "/");

			foreach (var pattern in patterns)
			{
				if (string.IsNullOrWhiteSpace(pattern))
				{
					continue;
				}

				var normalizedPattern = pattern.Replace("\\", "/");

				// Simple pattern matching: ** for any directory level, * for any characters in single level
				if (SimpleGlobMatch(normalizedPath, normalizedPattern))
				{
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// Performs simplified glob matching supporting <c>*</c> and <c>**</c> tokens.
		/// </summary>
		/// <param name="path">The normalized path to evaluate.</param>
		/// <param name="pattern">The normalized glob pattern.</param>
		/// <returns><see langword="true"/> when the path matches the pattern; otherwise <see langword="false"/>.</returns>
		private bool SimpleGlobMatch(string path, string pattern)
		{
			// Handle ** (any number of directory levels)
			if (pattern.Contains("**"))
			{
				var parts = pattern.Split(new[] { "**" }, StringSplitOptions.None);

				if (parts.Length == 1)
				{
					// No ** found, shouldn't happen, but handle gracefully
					return path.Equals(pattern, StringComparison.OrdinalIgnoreCase);
				}

				// Check start
				if (!string.IsNullOrEmpty(parts[0]))
				{
					if (!path.StartsWith(parts[0], StringComparison.OrdinalIgnoreCase))
					{
						return false;
					}
				}

				// Check end
				if (!string.IsNullOrEmpty(parts[parts.Length - 1]))
				{
					if (!path.EndsWith(parts[parts.Length - 1], StringComparison.OrdinalIgnoreCase))
					{
						return false;
					}
				}

				return true;
			}

			// Simple * pattern matching (matches anything in current path segment)
			if (pattern.Contains("*"))
			{
				var regexPattern = "^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*") + "$";

				return System.Text.RegularExpressions.Regex.IsMatch(path, regexPattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
			}

			// Exact match
			return path.Equals(pattern, StringComparison.OrdinalIgnoreCase);
		}
	}
}

