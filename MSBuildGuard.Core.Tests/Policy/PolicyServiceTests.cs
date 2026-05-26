using MSBuildGuard.Core.Policy;
using NUnit.Framework;
using Shouldly;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MSBuildGuard.Core.Tests.Policy
{
	/// <summary>
	/// Tests for <see cref="PolicyService"/>.
	/// </summary>
	[TestFixture]
	public sealed class PolicyServiceTests
	{
		/// <summary>
		/// Verifies precedence merge applies machine over repository over user over defaults.
		/// </summary>
		[Test]
		public void PolicyService_Merge_ShouldRespectPrecedence()
		{
			var service = new PolicyService();
			var defaults = service.CreateDefault();
			var user = new PolicyDocument { Mode = "warn", BaselineRequired = false, IncompleteAnalysisAction = PolicyAction.Warn, StrictMode = false, UnapprovedPackageSourceAction = PolicyAction.Warn };
			var repository = new PolicyDocument { Mode = "block", BaselineRequired = true, IncompleteAnalysisAction = PolicyAction.RequireApproval, StrictMode = false, UnapprovedPackageSourceAction = PolicyAction.RequireApproval };
			var machine = new PolicyDocument { Mode = "block", BaselineRequired = true, IncompleteAnalysisAction = PolicyAction.Block, StrictMode = true, UnapprovedPackageSourceAction = PolicyAction.Block };

			user.MinimumActionBySeverity[FindingSeverity.Medium] = PolicyAction.Warn;
			repository.MinimumActionBySeverity[FindingSeverity.Medium] = PolicyAction.RequireApproval;
			machine.MinimumActionBySeverity[FindingSeverity.Medium] = PolicyAction.Block;

			user.AllowedPackageSources.Add("https://user-feed.example/v3/index.json");
			repository.AllowedPackageSources.Add("https://repo-feed.example/v3/index.json");
			machine.AllowedPackageSources.Add("https://machine-feed.example/v3/index.json");
			user.BlockedPackageSources.Add("https://blocked-user-feed.example/v3/index.json");
			repository.BlockedPackageSources.Add("https://blocked-repo-feed.example/v3/index.json");
			machine.BlockedPackageSources.Add("https://blocked-machine-feed.example/v3/index.json");

			var merged = service.Merge(machine, repository, user, defaults);

			merged.BaselineRequired.ShouldBeTrue();
			merged.IncompleteAnalysisAction.ShouldBe(PolicyAction.Block);
			merged.MinimumActionBySeverity[FindingSeverity.Medium].ShouldBe(PolicyAction.Block);
			merged.StrictMode.ShouldBeTrue();
			merged.UnapprovedPackageSourceAction.ShouldBe(PolicyAction.Block);
			merged.AllowedPackageSources.ShouldBe(["https://machine-feed.example/v3/index.json"]);
			merged.BlockedPackageSources.ShouldBe(["https://blocked-machine-feed.example/v3/index.json"]);
		}

		/// <summary>
		/// Verifies the default policy includes package source controls.
		/// </summary>
		[Test]
		public void CreateDefault_ShouldInitializePackageSourceControls()
		{
			var service = new PolicyService();
			var policy = service.CreateDefault();

			policy.UnapprovedPackageSourceAction.ShouldBe(PolicyAction.RequireApproval);
			policy.AllowedPackageSources.ShouldBeEmpty();
			policy.BlockedPackageSources.ShouldBeEmpty();
		}

		/// <summary>
		/// Verifies MBG012 is blocked when strict mode is enabled.
		/// </summary>
		[Test]
		public void ResolveAction_ShouldBlockMbg012_WhenStrictModeIsEnabled()
		{
			var service = new PolicyService();
			var policy = service.CreateDefault();

			policy.IncompleteAnalysisAction = PolicyAction.RequireApproval;
			policy.StrictMode = true;

			var action = service.ResolveAction(policy, new Finding
			{
				Id = "MBG012",
				PolicyAction = PolicyAction.Warn,
				Severity = FindingSeverity.Medium
			});

			action.ShouldBe(PolicyAction.Block);
		}

		/// <summary>
		/// Verifies MBG012 uses configured incomplete-analysis action when strict mode is disabled.
		/// </summary>
		[Test]
		public void ResolveAction_ShouldUseIncompleteAnalysisAction_WhenStrictModeIsDisabled()
		{
			var service = new PolicyService();
			var policy = service.CreateDefault();

			policy.IncompleteAnalysisAction = PolicyAction.RequireApproval;
			policy.StrictMode = false;

			var action = service.ResolveAction(policy, new Finding
			{
				Id           = "MBG012",
				PolicyAction = PolicyAction.Warn,
				Severity     = FindingSeverity.Medium
			});

			action.ShouldBe(PolicyAction.RequireApproval);
		}

		/// <summary>
		/// Verifies signed policy validation succeeds immediately after signing.
		/// </summary>
		[Test]
		public void SignAndValidate_ShouldSucceed_WhenPolicyHasNotChanged()
		{
			if (!OperatingSystem.IsWindows())
			{
				Assert.Ignore("Policy signature stream tests require Windows NTFS alternate stream support.");
			}

			var service = new PolicyService();
			var policyPath = Path.Combine(Path.GetTempPath(), $"policy-sign-{Guid.NewGuid():N}.json");
			using var certificate = CreateSelfSignedCertificate();

			AddCertificate(StoreName.My, StoreLocation.CurrentUser, certificate);
			AddCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate);
			Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", "true");

			try
			{
				service.Save(policyPath, service.CreateDefault());
				service.Sign(policyPath, certificate.Thumbprint);

				service.TryValidateSignature(policyPath, out var message).ShouldBeTrue(message);
			}
			finally
			{
				Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", null);
				RemoveCertificate(StoreName.My, StoreLocation.CurrentUser, certificate.Thumbprint);
				RemoveCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate.Thumbprint);
			}
		}

		/// <summary>
		/// Verifies loading succeeds when no external signature stream exists but the JSON envelope is valid.
		/// </summary>
		[Test]
		public void Load_ShouldSucceed_WhenNoExternalSignatureExistsAndJsonEnvelopeIsValid()
		{
			var service = new PolicyService();
			var policyPath = Path.Combine(Path.GetTempPath(), $"policy-load-{Guid.NewGuid():N}.json");

			service.Save(policyPath, service.CreateDefault());

			var policy = service.Load(policyPath);

			policy.ShouldNotBeNull();
			service.TryValidateSignature(policyPath, out var message).ShouldBeTrue(message);
			message.ShouldContain("No external policy signature was found");
		}

		/// <summary>
		/// Verifies loading a raw JSON policy with string-based enums succeeds.
		/// </summary>
		[Test]
		public void Load_ShouldSucceed_WhenRawJsonHasStringEnums()
		{
			var service = new PolicyService();
			var policyPath = Path.Combine(Path.GetTempPath(), $"policy-string-enums-{Guid.NewGuid():N}.json");
			var rawJson = "{\r\n  \"Version\": 1,\r\n  \"Mode\": \"warn\",\r\n  \"BaselineRequired\": false,\r\n  \"StrictMode\": false,\r\n  \"IncompleteAnalysisAction\": \"warn\",\r\n  \"UnapprovedPackageSourceAction\": \"requireApproval\",\r\n  \"MinimumActionBySeverity\": {\r\n    \"Info\": \"allow\",\r\n    \"Low\": \"warn\",\r\n    \"Medium\": \"requireApproval\",\r\n    \"High\": \"block\",\r\n    \"Critical\": \"block\"\r\n  },\r\n  \"Rules\": {},\r\n  \"Include\": [],\r\n  \"Exclude\": [],\r\n  \"AllowedPackageSources\": [],\r\n  \"BlockedPackageSources\": []\r\n}";

			try
			{
				File.WriteAllText(policyPath, rawJson);

				var policy = service.LoadUnsigned(policyPath);

				policy.ShouldNotBeNull();

				policy.IncompleteAnalysisAction.ShouldBe(PolicyAction.Warn);
				policy.UnapprovedPackageSourceAction.ShouldBe(PolicyAction.RequireApproval);
				policy.MinimumActionBySeverity[FindingSeverity.Critical].ShouldBe(PolicyAction.Block);
			}
			finally
			{
				if (File.Exists(policyPath))
				{
					File.Delete(policyPath);
				}
			}
		}

		/// <summary>
		/// Verifies loading fails when the policy JSON content is unsigned.
		/// </summary>
		[Test]
		public void Load_ShouldThrow_WhenPolicyIsUnsigned()
		{
			var service = new PolicyService();
			var policyPath = Path.Combine(Path.GetTempPath(), $"policy-unsigned-{Guid.NewGuid():N}.json");
			var rawJson = "{\r\n  \"Version\": 1,\r\n  \"Mode\": \"warn\"\r\n}";

			try
			{
				File.WriteAllText(policyPath, rawJson);

				Should.Throw<InvalidDataException>(() => service.Load(policyPath));
			}
			finally
			{
				if (File.Exists(policyPath))
				{
					File.Delete(policyPath);
				}
			}
		}

		/// <summary>
		/// Verifies validation fails when the JSON envelope has been modified without a matching signature.
		/// </summary>
		[Test]
		public void TryValidateSignature_ShouldFail_WhenJsonEnvelopeIsInvalidWithoutExternalSignature()
		{
			var service = new PolicyService();
			var policyPath = Path.Combine(Path.GetTempPath(), $"policy-invalid-envelope-{Guid.NewGuid():N}.json");

			service.Save(policyPath, service.CreateDefault());

			File.WriteAllText(policyPath, "{\"invalid\":true}");

			service.TryValidateSignature(policyPath, out var message).ShouldBeFalse();
			message.ShouldContain("Policy signature validation failed");
		}

		/// <summary>
		/// Verifies signed policy validation fails after policy content is modified.
		/// </summary>
		[Test]
		public void Validate_ShouldFail_WhenPolicyContentWasModifiedAfterSigning()
		{
			if (!OperatingSystem.IsWindows())
			{
				Assert.Ignore("Policy signature stream tests require Windows NTFS alternate stream support.");
			}

			var service = new PolicyService();
			var policyPath = Path.Combine(Path.GetTempPath(), $"policy-tamper-{Guid.NewGuid():N}.json");
			using var certificate = CreateSelfSignedCertificate();

			AddCertificate(StoreName.My, StoreLocation.CurrentUser, certificate);
			AddCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate);
			Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", "true");

			try
			{
				service.Save(policyPath, service.CreateDefault());
				service.Sign(policyPath, certificate.Thumbprint);

				using (var stream = new FileStream(policyPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
				{
					var firstByte = stream.ReadByte();
					stream.Position = 0;
					stream.WriteByte(firstByte == '{' ? (byte)'}' : (byte)'{');
				}

				service.TryValidateSignature(policyPath, out var message).ShouldBeFalse();
				message.ShouldContain("Policy signature validation failed");
			}
			finally
			{
				Environment.SetEnvironmentVariable("MSBUILDGUARD_POLICY_ALLOW_CURRENTUSER_TRUSTED_STORE", null);
				RemoveCertificate(StoreName.My, StoreLocation.CurrentUser, certificate.Thumbprint);
				RemoveCertificate(StoreName.TrustedPeople, StoreLocation.CurrentUser, certificate.Thumbprint);
			}
		}

		/// <summary>
		/// Verifies loading a raw JSON policy with lowercase enum keys succeeds.
		/// </summary>
		[Test]
		public void Load_ShouldSucceed_WhenRawJsonHasLowercaseEnumKeys()
		{
			var service = new PolicyService();
			var policyPath = Path.Combine(Path.GetTempPath(), $"policy-lowercase-enums-{Guid.NewGuid():N}.json");
			var rawJson = "{\r\n  \"Version\": 1,\r\n  \"Mode\": \"warn\",\r\n  \"BaselineRequired\": false,\r\n  \"StrictMode\": false,\r\n  \"IncompleteAnalysisAction\": \"warn\",\r\n  \"UnapprovedPackageSourceAction\": \"requireApproval\",\r\n  \"MinimumActionBySeverity\": {\r\n    \"info\": \"allow\",\r\n    \"low\": \"warn\",\r\n    \"medium\": \"requireApproval\",\r\n    \"high\": \"block\",\r\n    \"critical\": \"block\"\r\n  },\r\n  \"Rules\": {},\r\n  \"Include\": [],\r\n  \"Exclude\": [],\r\n  \"AllowedPackageSources\": [],\r\n  \"BlockedPackageSources\": []\r\n}";

			try
			{
				File.WriteAllText(policyPath, rawJson);

				var policy = service.LoadUnsigned(policyPath);

				policy.ShouldNotBeNull();
				policy.MinimumActionBySeverity[FindingSeverity.Critical].ShouldBe(PolicyAction.Block);
				policy.MinimumActionBySeverity[FindingSeverity.High].ShouldBe(PolicyAction.Block);
				policy.MinimumActionBySeverity[FindingSeverity.Medium].ShouldBe(PolicyAction.RequireApproval);
				policy.MinimumActionBySeverity[FindingSeverity.Low].ShouldBe(PolicyAction.Warn);
				policy.MinimumActionBySeverity[FindingSeverity.Info].ShouldBe(PolicyAction.Allow);
			}
			finally
			{
				if (File.Exists(policyPath))
				{
					File.Delete(policyPath);
				}
			}
		}



		private static X509Certificate2 CreateSelfSignedCertificate()
		{
			using var rsa = RSA.Create(2048);
			var request = new CertificateRequest(
				$"CN=MSBuildGuard-PolicyTests-{Guid.NewGuid():N}",
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
