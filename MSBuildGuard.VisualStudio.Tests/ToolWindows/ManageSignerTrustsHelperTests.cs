using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.ToolWindows;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.VisualStudio.ToolWindows.Tests
{
	/// <summary>
	/// Unit tests for the <see cref="ManageSignerTrustsHelper"/> class.
	/// </summary>
	[TestFixture]
	public sealed class ManageSignerTrustsHelperTests
	{
		private string tempDir = string.Empty;

		/// <summary>
		/// Sets up the test environment.
		/// </summary>
		[SetUp]
		public void SetUp()
		{
			this.tempDir = Path.Combine(Path.GetTempPath(), "MSBuildGuardTests", Guid.NewGuid().ToString("N"));

			Directory.CreateDirectory(this.tempDir);
		}

		/// <summary>
		/// Tears down the test environment.
		/// </summary>
		[TearDown]
		public void TearDown()
		{
			if (Directory.Exists(this.tempDir))
			{
				try
				{
					Directory.Delete(this.tempDir, true);
				}
				catch
				{
					// Ignore clean up errors.
				}
			}
		}

		/// <summary>
		/// Verifies that <see cref="ManageSignerTrustsHelper.InitializeProjectOptions"/> correctly initializes project options.
		/// </summary>
		[Test]
		public void InitializeProjectOptions_PopulatesProjectOptionsCorrectly()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var projectPath  = Path.Combine(this.tempDir, "TestProj.csproj");
			var helper       = new ManageSignerTrustsHelper(solutionPath, projectPath);
			var paths        = new[]
			{
				Path.Combine(this.tempDir, "Proj1.csproj"),
				Path.Combine(this.tempDir, "Proj2.csproj"),
				Path.Combine(this.tempDir, "Proj1.csproj"), // Duplicate
				"", // Empty
				null // Null
			};

			helper.InitializeProjectOptions(paths!);

			helper.ProjectOptions.Count.ShouldBe(2);
			helper.ProjectOptions[0].Name.ShouldBe("Proj1");
			helper.ProjectOptions[0].Path.ShouldBe(paths[0]);
			helper.ProjectOptions[1].Name.ShouldBe("Proj2");
			helper.ProjectOptions[1].Path.ShouldBe(paths[1]);
		}

		/// <summary>
		/// Verifies that <see cref="ManageSignerTrustsHelper.ResolveTrustStorePath"/> resolves trust store path correctly.
		/// </summary>
		[Test]
		public void ResolveTrustStorePath_ResolvesPathsForDifferentScopes()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var projectPath  = Path.Combine(this.tempDir, "TestProj.csproj");
			var helper       = new ManageSignerTrustsHelper(solutionPath, projectPath);
			var userPath     = helper.ResolveTrustStorePath(TrustScope.User, string.Empty);

			userPath.ShouldContain("trust.json");

			var solPath = helper.ResolveTrustStorePath(TrustScope.Solution, string.Empty);

			solPath.ShouldBe(Path.Combine(this.tempDir, ".msbuildguard", "trust.json"));

			var projPath = helper.ResolveTrustStorePath(TrustScope.Project, projectPath);

			projPath.ShouldBe(Path.Combine(this.tempDir, ".msbuildguard", "trust.json"));
		}

		/// <summary>
		/// Verifies removing trusted signers updates the collection and tracks changes.
		/// </summary>
		[Test]
		public void RemoveTrustedSigner_ManipulatesCollectionAndTracksChanges()
		{
			var helper = new ManageSignerTrustsHelper(string.Empty, string.Empty);

			helper.HasChanges.ShouldBeFalse();

			var item = new SignerTrustItem
			{
				SignerName = "TestSigner",
				SubjectDn  = "CN=TestSigner",
				Issuer     = "CN=TestIssuer",
				Reason     = "Trusted signer"
			};

			helper.TrustedSigners.Add(item);

			helper.RemoveTrustedSigner(item);

			helper.TrustedSigners.ShouldBeEmpty();
			helper.HasChanges.ShouldBeTrue();
		}

		/// <summary>
		/// Verifies that <see cref="ManageSignerTrustsHelper.LoadTrustedSigners"/> loads correctly from a trust store.
		/// </summary>
		[Test]
		public void LoadTrustedSigners_LoadsSignersFromStore()
		{
			var projectPath   = Path.Combine(this.tempDir, "TestProj.csproj");
			var trustStoreDir = Path.Combine(this.tempDir, ".msbuildguard");

			Directory.CreateDirectory(trustStoreDir);

			var trustStorePath = Path.Combine(trustStoreDir, "trust.json");
			var json           = @"{
				""Decisions"": [
					{
						""DecisionId"": ""1"",
						""Scope"": ""Signer"",
						""SubjectHash"": ""CN=SignerA"",
						""AssemblySigner"": ""SignerA"",
						""AssemblyIssuer"": ""IssuerA"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonA"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					},
					{
						""DecisionId"": ""2"",
						""Scope"": ""Signer"",
						""SubjectHash"": ""CN=SignerB"",
						""AssemblySigner"": ""SignerB"",
						""AssemblyIssuer"": ""IssuerB"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonB"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					},
					{
						""DecisionId"": ""3"",
						""Scope"": ""Assembly"",
						""SubjectHash"": ""hashC"",
						""AssemblySigner"": ""SomeAssembly"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonC"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					}
				]
			}";

			var doc = JsonSerializer.Deserialize<TrustStoreDocument>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } });
			new TrustStoreService().Save(trustStorePath, doc!);

			var helper = new ManageSignerTrustsHelper(string.Empty, projectPath);

			helper.LoadTrustedSigners(TrustScope.Project, projectPath);

			helper.TrustedSigners.Count.ShouldBe(2);

			var sA = helper.TrustedSigners.First(s => s.SignerName == "SignerA");

			sA.SubjectDn.ShouldBe("CN=SignerA");
			sA.Issuer.ShouldBe("IssuerA");
			sA.Reason.ShouldBe("ReasonA");

			var sB = helper.TrustedSigners.First(s => s.SignerName == "SignerB");

			sB.SubjectDn.ShouldBe("CN=SignerB");
			sB.Issuer.ShouldBe("IssuerB");
			sB.Reason.ShouldBe("ReasonB");
		}

		/// <summary>
		/// Verifies that <see cref="ManageSignerTrustsHelper.Save"/> correctly serializes and writes decisions to disk.
		/// </summary>
		[Test]
		public void Save_WritesTrustedSignersToStore()
		{
			var projectPath = Path.Combine(this.tempDir, "TestProj.csproj");
			var helper      = new ManageSignerTrustsHelper(string.Empty, projectPath);

			helper.LoadTrustedSigners(TrustScope.Project, projectPath);

			var item = new SignerTrustItem
			{
				SignerName = "TestSigner",
				SubjectDn  = "CN=TestSigner",
				Issuer     = "CN=TestIssuer",
				Reason     = "Trusted signer"
			};

			helper.TrustedSigners.Add(item);

			// Trigger HasChanges = true by using helper removal/add (or manually editing HasChanges is not allowed since it is private set, so we use helper API).
			// Instead of direct Add, let's remove and add back, or mock Load and save.
			// Actually, let's just use RemoveTrustedSigner on an existing list or edit helper to have changes.
			// Since we want HasChanges to be true, we can do:
			helper.RemoveTrustedSigner(null!); // No op
			// Let's create an entry in the file first, load it, then remove it.
			var trustStoreDir = Path.Combine(this.tempDir, ".msbuildguard");

			Directory.CreateDirectory(trustStoreDir);

			var trustStorePath = Path.Combine(trustStoreDir, "trust.json");
			var json           = @"{
				""Decisions"": [
					{
						""DecisionId"": ""1"",
						""Scope"": ""Signer"",
						""SubjectHash"": ""CN=SignerA"",
						""AssemblySigner"": ""SignerA"",
						""AssemblyIssuer"": ""IssuerA"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonA"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					}
				]
			}";

			var doc = JsonSerializer.Deserialize<TrustStoreDocument>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } });
			new TrustStoreService().Save(trustStorePath, doc!);

			helper.LoadTrustedSigners(TrustScope.Project, projectPath);

			var signer = helper.TrustedSigners.First();

			helper.RemoveTrustedSigner(signer);

			helper.Save("TestUserSid");

			// Reload using a fresh helper to verify persistence
			var verifier = new ManageSignerTrustsHelper(string.Empty, projectPath);

			verifier.LoadTrustedSigners(TrustScope.Project, projectPath);

			verifier.TrustedSigners.Count.ShouldBe(0);
		}

		/// <summary>
		/// Verifies that <see cref="ManageSignerTrustsHelper.MoveTrustToScope"/> relocates trust decisions from one scope to another.
		/// </summary>
		[Test]
		public void MoveTrustToScope_RelocatesDecisionToAnotherStore()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var projectAPath = Path.Combine(this.tempDir, "ProjA", "ProjA.csproj");
			var projectBPath = Path.Combine(this.tempDir, "ProjB", "ProjB.csproj");
			var helper       = new ManageSignerTrustsHelper(solutionPath, projectAPath);

			var trustStoreDir = Path.Combine(this.tempDir, "ProjA", ".msbuildguard");

			Directory.CreateDirectory(trustStoreDir);

			var trustStorePath = Path.Combine(trustStoreDir, "trust.json");
			var json           = @"{
				""Decisions"": [
					{
						""DecisionId"": ""1"",
						""Scope"": ""Signer"",
						""SubjectHash"": ""CN=SignerA"",
						""AssemblySigner"": ""SignerA"",
						""AssemblyIssuer"": ""IssuerA"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonA"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					}
				]
			}";

			var doc = JsonSerializer.Deserialize<TrustStoreDocument>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } });
			new TrustStoreService().Save(trustStorePath, doc!);

			helper.LoadTrustedSigners(TrustScope.Project, projectAPath);

			var selectedTrust = helper.TrustedSigners.First();

			helper.MoveTrustToScope(selectedTrust, TrustScope.Project, TrustScope.Project, projectAPath, projectBPath, "UserSid");

			helper.TrustedSigners.ShouldBeEmpty();
			helper.HasMovedTrust.ShouldBeTrue();

			var sourceVerifier = new ManageSignerTrustsHelper(solutionPath, projectAPath);

			sourceVerifier.LoadTrustedSigners(TrustScope.Project, projectAPath);
			sourceVerifier.TrustedSigners.ShouldBeEmpty();

			var destVerifier = new ManageSignerTrustsHelper(solutionPath, projectBPath);

			destVerifier.LoadTrustedSigners(TrustScope.Project, projectBPath);
			destVerifier.TrustedSigners.Count.ShouldBe(1);
			destVerifier.TrustedSigners.First().SignerName.ShouldBe("SignerA");
		}
	}
}
