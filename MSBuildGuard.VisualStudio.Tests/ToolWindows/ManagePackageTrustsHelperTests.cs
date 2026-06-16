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
	/// Unit tests for the <see cref="ManagePackageTrustsHelper"/> class.
	/// </summary>
	[TestFixture]
	public sealed class ManagePackageTrustsHelperTests
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
		/// Verifies that <see cref="ManagePackageTrustsHelper.InitializeProjectOptions"/> correctly initializes project options.
		/// </summary>
		[Test]
		public void InitializeProjectOptions_PopulatesProjectOptionsCorrectly()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var projectPath  = Path.Combine(this.tempDir, "TestProj.csproj");
			var helper       = new ManagePackageTrustsHelper(solutionPath, projectPath);
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
		/// Verifies that <see cref="ManagePackageTrustsHelper.ResolveTrustStorePath"/> resolves trust store path correctly.
		/// </summary>
		[Test]
		public void ResolveTrustStorePath_ResolvesPathsForDifferentScopes()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var projectPath  = Path.Combine(this.tempDir, "TestProj.csproj");
			var helper       = new ManagePackageTrustsHelper(solutionPath, projectPath);
			var userPath     = helper.ResolveTrustStorePath(TrustScope.User, string.Empty);

			userPath.ShouldContain("trust.json");

			var solPath = helper.ResolveTrustStorePath(TrustScope.Solution, string.Empty);

			solPath.ShouldBe(Path.Combine(this.tempDir, ".msbuildguard", "trust.json"));

			var projPath = helper.ResolveTrustStorePath(TrustScope.Project, projectPath);

			projPath.ShouldBe(Path.Combine(this.tempDir, ".msbuildguard", "trust.json"));
		}

		/// <summary>
		/// Verifies that <see cref="ManagePackageTrustsHelper.IsPackageAlreadyTrusted"/> detects duplicate trust entries.
		/// </summary>
		[Test]
		public void IsPackageAlreadyTrusted_ChecksDuplicatesCorrectly()
		{
			var helper = new ManagePackageTrustsHelper(string.Empty, string.Empty);

			helper.AddTrustedPackage("Newtonsoft.Json", "13.0.1", "hash1", "reason1");

			helper.IsPackageAlreadyTrusted("Newtonsoft.Json", "13.0.1").ShouldBeTrue();
			helper.IsPackageAlreadyTrusted("newtonsoft.json", "13.0.1").ShouldBeTrue(); // Case insensitive
			helper.IsPackageAlreadyTrusted("Newtonsoft.Json", "12.0.1").ShouldBeFalse();
		}

		/// <summary>
		/// Verifies adding and removing trusted packages updates the collection and tracks changes.
		/// </summary>
		[Test]
		public void AddAndRemoveTrustedPackage_ManipulatesCollectionAndTracksChanges()
		{
			var helper = new ManagePackageTrustsHelper(string.Empty, string.Empty);

			helper.HasChanges.ShouldBeFalse();

			helper.AddTrustedPackage("Newtonsoft.Json", "13.0.1", "hash1", "reason1");

			helper.TrustedPackages.Count.ShouldBe(1);
			helper.HasChanges.ShouldBeTrue();

			var item = helper.TrustedPackages.First();

			item.Name.ShouldBe("Newtonsoft.Json");
			item.Version.ShouldBe("13.0.1");
			item.Hash.ShouldBe("hash1");
			item.Reason.ShouldBe("reason1");
			item.Subject.ShouldBe("newtonsoft.json@13.0.1");

			helper.ClearChanges();
			helper.HasChanges.ShouldBeFalse();

			helper.RemoveTrustedPackage(item);

			helper.TrustedPackages.ShouldBeEmpty();
			helper.HasChanges.ShouldBeTrue();
		}

		/// <summary>
		/// Verifies that <see cref="ManagePackageTrustsHelper.ParseNuspec"/> successfully extracts metadata from nuspec XML content.
		/// </summary>
		[Test]
		public void ParseNuspec_ParsesXmlManifestCorrectly()
		{
			var nuspecPath = Path.Combine(this.tempDir, "TestPkg.nuspec");
			var xml        = @"<?xml version=""1.0"" encoding=""utf-8""?>
<package xmlns=""http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd"">
  <metadata>
    <id>TestPackage.Id</id>
    <version>1.2.3-beta</version>
  </metadata>
</package>";

			File.WriteAllText(nuspecPath, xml);

			ManagePackageTrustsHelper.ParseNuspec(nuspecPath, out var packageId, out var packageVersion);

			packageId.ShouldBe("TestPackage.Id");
			packageVersion.ShouldBe("1.2.3-beta");
		}

		/// <summary>
		/// Verifies that <see cref="ManagePackageTrustsHelper.LoadTrustedPackages"/> loads correctly from a trust store.
		/// </summary>
		[Test]
		public void LoadTrustedPackages_LoadsPackagesFromStore()
		{
			var projectPath   = Path.Combine(this.tempDir, "TestProj.csproj");
			var trustStoreDir = Path.Combine(this.tempDir, ".msbuildguard");

			Directory.CreateDirectory(trustStoreDir);

			var trustStorePath = Path.Combine(trustStoreDir, "trust.json");
			var json           = @"{
				""Decisions"": [
					{
						""DecisionId"": ""1"",
						""Scope"": ""Package"",
						""SubjectHash"": ""hashA"",
						""AssemblySigner"": ""PkgA@1.0.0"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonA"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					},
					{
						""DecisionId"": ""2"",
						""Scope"": ""Package"",
						""SubjectHash"": ""hashB"",
						""AssemblySigner"": ""PkgB@2.0.0"",
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

			var helper = new ManagePackageTrustsHelper(string.Empty, projectPath);

			helper.LoadTrustedPackages(TrustScope.Project, projectPath);

			helper.TrustedPackages.Count.ShouldBe(2);

			var pA = helper.TrustedPackages.First(p => p.Name == "PkgA");

			pA.Version.ShouldBe("1.0.0");
			pA.Hash.ShouldBe("hashA");
			pA.Reason.ShouldBe("ReasonA");
			pA.Subject.ShouldBe("PkgA@1.0.0");

			var pB = helper.TrustedPackages.First(p => p.Name == "PkgB");

			pB.Version.ShouldBe("2.0.0");
			pB.Hash.ShouldBe("hashB");
			pB.Reason.ShouldBe("ReasonB");
			pB.Subject.ShouldBe("PkgB@2.0.0");
		}

		/// <summary>
		/// Verifies that <see cref="ManagePackageTrustsHelper.Save"/> correctly serializes and writes decisions to disk.
		/// </summary>
		[Test]
		public void Save_WritesTrustedPackagesToStore()
		{
			var projectPath = Path.Combine(this.tempDir, "TestProj.csproj");
			var helper      = new ManagePackageTrustsHelper(string.Empty, projectPath);

			helper.LoadTrustedPackages(TrustScope.Project, projectPath);
			helper.AddTrustedPackage("Newtonsoft.Json", "13.0.1", "hash1", "reason1");

			helper.Save("TestUserSid");

			var verifier = new ManagePackageTrustsHelper(string.Empty, projectPath);

			verifier.LoadTrustedPackages(TrustScope.Project, projectPath);

			verifier.TrustedPackages.Count.ShouldBe(1);

			var item = verifier.TrustedPackages.First();

			item.Name.ShouldBe("newtonsoft.json");
			item.Version.ShouldBe("13.0.1");
			item.Hash.ShouldBe("hash1");
			item.Reason.ShouldBe("reason1");
		}

		/// <summary>
		/// Verifies that <see cref="ManagePackageTrustsHelper.MoveTrustToScope"/> relocates trust decisions from one scope to another.
		/// </summary>
		[Test]
		public void MoveTrustToScope_RelocatesDecisionToAnotherStore()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var projectAPath = Path.Combine(this.tempDir, "ProjA", "ProjA.csproj");
			var projectBPath = Path.Combine(this.tempDir, "ProjB", "ProjB.csproj");
			var helper       = new ManagePackageTrustsHelper(solutionPath, projectAPath);

			helper.LoadTrustedPackages(TrustScope.Project, projectAPath);
			helper.AddTrustedPackage("Newtonsoft.Json", "13.0.1", "hash1", "reason1");
			helper.Save("UserSid");

			var selectedTrust = helper.TrustedPackages.First();

			helper.MoveTrustToScope(selectedTrust, TrustScope.Project, TrustScope.Project, projectAPath, projectBPath, "UserSid");

			helper.TrustedPackages.ShouldBeEmpty();
			helper.HasMovedTrust.ShouldBeTrue();

			var sourceVerifier = new ManagePackageTrustsHelper(solutionPath, projectAPath);

			sourceVerifier.LoadTrustedPackages(TrustScope.Project, projectAPath);
			sourceVerifier.TrustedPackages.ShouldBeEmpty();

			var destVerifier = new ManagePackageTrustsHelper(solutionPath, projectBPath);

			destVerifier.LoadTrustedPackages(TrustScope.Project, projectBPath);
			destVerifier.TrustedPackages.Count.ShouldBe(1);
			destVerifier.TrustedPackages.First().Name.ShouldBe("newtonsoft.json");
		}
	}
}
