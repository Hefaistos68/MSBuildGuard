using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using MSBuildGuard.Core.Trust;
using MSBuildGuard.VisualStudio.Models;
using MSBuildGuard.VisualStudio.ToolWindows;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.VisualStudio.ToolWindows.Tests
{
	/// <summary>
	/// Unit tests for the <see cref="ManageAssemblyTrustsHelper"/> class.
	/// </summary>
	[TestFixture]
	public sealed class ManageAssemblyTrustsHelperTests
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
		/// Verifies that <see cref="ManageAssemblyTrustsHelper.InitializeProjectOptions"/> correctly initializes project options.
		/// </summary>
		[Test]
		public void InitializeProjectOptions_PopulatesProjectOptionsCorrectly()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var projectPath  = Path.Combine(this.tempDir, "TestProj.csproj");
			var helper       = new ManageAssemblyTrustsHelper(solutionPath, projectPath);
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
		/// Verifies that <see cref="ManageAssemblyTrustsHelper.ResolveTrustStorePath"/> resolves trust store path correctly.
		/// </summary>
		[Test]
		public void ResolveTrustStorePath_ResolvesPathsForDifferentScopes()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var projectPath  = Path.Combine(this.tempDir, "TestProj.csproj");
			var helper       = new ManageAssemblyTrustsHelper(solutionPath, projectPath);
			var userPath     = helper.ResolveTrustStorePath(TrustScope.User, string.Empty);

			userPath.ShouldContain("trust.json");

			var solPath = helper.ResolveTrustStorePath(TrustScope.Solution, string.Empty);

			solPath.ShouldBe(Path.Combine(this.tempDir, ".msbuildguard", "trust.json"));

			var projPath = helper.ResolveTrustStorePath(TrustScope.Project, projectPath);

			projPath.ShouldBe(Path.Combine(this.tempDir, ".msbuildguard", "trust.json"));
		}

		/// <summary>
		/// Verifies static helper methods extract name and version correctly.
		/// </summary>
		[Test]
		public void ExtractAssemblyNameAndVersion_ParsesSubjectCorrectly()
		{
			ManageAssemblyTrustsHelper.ExtractAssemblyName("Newtonsoft.Json@13.0.1").ShouldBe("Newtonsoft.Json");
			ManageAssemblyTrustsHelper.ExtractAssemblyVersion("Newtonsoft.Json@13.0.1").ShouldBe("13.0.1");

			ManageAssemblyTrustsHelper.ExtractAssemblyName("NoVersion").ShouldBe("NoVersion");
			ManageAssemblyTrustsHelper.ExtractAssemblyVersion("NoVersion").ShouldBeEmpty();

			ManageAssemblyTrustsHelper.ExtractAssemblyName(null!).ShouldBeEmpty();
			ManageAssemblyTrustsHelper.ExtractAssemblyVersion(null!).ShouldBeEmpty();
		}

		/// <summary>
		/// Verifies adding and removing trusted assemblies updates the collection and tracks changes.
		/// </summary>
		[Test]
		public void AddAndRemoveTrustedAssembly_ManipulatesCollectionAndTracksChanges()
		{
			var helper = new ManageAssemblyTrustsHelper(string.Empty, string.Empty);

			helper.HasChanges.ShouldBeFalse();

			helper.AddTrustedAssembly("Newtonsoft.Json", "13.0.1", "CN=Test", "CN=Issuer", "CN=Test", "Reason");

			helper.TrustedAssemblies.Count.ShouldBe(1);
			helper.HasChanges.ShouldBeTrue();

			var item = helper.TrustedAssemblies.First();

			item.Name.ShouldBe("Newtonsoft.Json");
			item.Version.ShouldBe("13.0.1");
			item.Signer.ShouldBe("CN=Test");
			item.Issuer.ShouldBe("CN=Issuer");
			item.SubjectName.ShouldBe("CN=Test");
			item.Reason.ShouldBe("Reason");
			item.Subject.ShouldBe("Newtonsoft.Json@13.0.1");

			helper.ClearChanges();
			helper.HasChanges.ShouldBeFalse();

			helper.RemoveTrustedAssembly(item);

			helper.TrustedAssemblies.ShouldBeEmpty();
			helper.HasChanges.ShouldBeTrue();
		}

		/// <summary>
		/// Verifies that <see cref="ManageAssemblyTrustsHelper.LoadTrustedAssemblies"/> loads correctly from a trust store.
		/// </summary>
		[Test]
		public void LoadTrustedAssemblies_LoadsAssembliesFromStore()
		{
			var projectPath   = Path.Combine(this.tempDir, "TestProj.csproj");
			var trustStoreDir = Path.Combine(this.tempDir, ".msbuildguard");

			Directory.CreateDirectory(trustStoreDir);

			var trustStorePath = Path.Combine(trustStoreDir, "trust.json");
			var json           = @"{
				""Decisions"": [
					{
						""DecisionId"": ""1"",
						""Scope"": ""Assembly"",
						""SubjectHash"": ""AssemblyA@1.0.0"",
						""AssemblySigner"": ""SignerA"",
						""AssemblyIssuer"": ""IssuerA"",
						""AssemblySubject"": ""CN=AssemblyA"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonA"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					},
					{
						""DecisionId"": ""2"",
						""Scope"": ""Assembly"",
						""SubjectHash"": ""AssemblyB@2.0.0"",
						""AssemblySigner"": ""SignerB"",
						""AssemblyIssuer"": ""IssuerB"",
						""AssemblySubject"": ""CN=AssemblyB"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonB"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					},
					{
						""DecisionId"": ""3"",
						""Scope"": ""Signer"",
						""SubjectHash"": ""CN=SomeSigner"",
						""AssemblySigner"": ""SomeSigner"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonC"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					}
				]
			}";

			File.WriteAllText(trustStorePath, json);

			var helper = new ManageAssemblyTrustsHelper(string.Empty, projectPath);

			helper.LoadTrustedAssemblies(TrustScope.Project, projectPath);

			helper.TrustedAssemblies.Count.ShouldBe(2);

			var aA = helper.TrustedAssemblies.First(a => a.Name == "AssemblyA");

			aA.Version.ShouldBe("1.0.0");
			aA.Signer.ShouldBe("SignerA");
			aA.Issuer.ShouldBe("IssuerA");
			aA.Reason.ShouldBe("ReasonA");

			var aB = helper.TrustedAssemblies.First(a => a.Name == "AssemblyB");

			aB.Version.ShouldBe("2.0.0");
			aB.Signer.ShouldBe("SignerB");
			aB.Issuer.ShouldBe("IssuerB");
			aB.Reason.ShouldBe("ReasonB");
		}

		/// <summary>
		/// Verifies that <see cref="ManageAssemblyTrustsHelper.Save"/> correctly serializes and writes decisions to disk.
		/// </summary>
		[Test]
		public void Save_WritesTrustedAssembliesToStore()
		{
			var projectPath = Path.Combine(this.tempDir, "TestProj.csproj");
			var helper      = new ManageAssemblyTrustsHelper(string.Empty, projectPath);

			helper.LoadTrustedAssemblies(TrustScope.Project, projectPath);

			helper.AddTrustedAssembly("AssemblyA", "1.0.0", "SignerA", "IssuerA", "CN=AssemblyA", "ReasonA");

			helper.Save("TestUserSid");

			var verifier = new ManageAssemblyTrustsHelper(string.Empty, projectPath);

			verifier.LoadTrustedAssemblies(TrustScope.Project, projectPath);

			verifier.TrustedAssemblies.Count.ShouldBe(1);

			var loaded = verifier.TrustedAssemblies.First();

			loaded.Name.ShouldBe("AssemblyA");
			loaded.Version.ShouldBe("1.0.0");
			loaded.Signer.ShouldBe("SignerA");
			loaded.Issuer.ShouldBe("IssuerA");
		}

		/// <summary>
		/// Verifies that <see cref="ManageAssemblyTrustsHelper.MoveTrustToScope"/> relocates trust decisions from one scope to another.
		/// </summary>
		[Test]
		public void MoveTrustToScope_RelocatesDecisionToAnotherStore()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var projectAPath = Path.Combine(this.tempDir, "ProjA", "ProjA.csproj");
			var projectBPath = Path.Combine(this.tempDir, "ProjB", "ProjB.csproj");
			var helper       = new ManageAssemblyTrustsHelper(solutionPath, projectAPath);

			var trustStoreDir = Path.Combine(this.tempDir, "ProjA", ".msbuildguard");

			Directory.CreateDirectory(trustStoreDir);

			var trustStorePath = Path.Combine(trustStoreDir, "trust.json");
			var json           = @"{
				""Decisions"": [
					{
						""DecisionId"": ""1"",
						""Scope"": ""Assembly"",
						""SubjectHash"": ""AssemblyA@1.0.0"",
						""AssemblySigner"": ""SignerA"",
						""AssemblyIssuer"": ""IssuerA"",
						""AssemblySubject"": ""CN=AssemblyA"",
						""Decision"": ""Trust"",
						""Reason"": ""ReasonA"",
						""UserSid"": ""sid1"",
						""CreatedAtUtc"": ""2026-06-12T00:00:00Z""
					}
				]
			}";

			File.WriteAllText(trustStorePath, json);

			helper.LoadTrustedAssemblies(TrustScope.Project, projectAPath);

			var selectedTrust = helper.TrustedAssemblies.First();

			helper.MoveTrustToScope(selectedTrust, TrustScope.Project, TrustScope.Project, projectAPath, projectBPath, "UserSid");

			helper.TrustedAssemblies.ShouldBeEmpty();
			helper.HasMovedTrust.ShouldBeTrue();

			var sourceVerifier = new ManageAssemblyTrustsHelper(solutionPath, projectAPath);

			sourceVerifier.LoadTrustedAssemblies(TrustScope.Project, projectAPath);
			sourceVerifier.TrustedAssemblies.ShouldBeEmpty();

			var destVerifier = new ManageAssemblyTrustsHelper(solutionPath, projectBPath);

			destVerifier.LoadTrustedAssemblies(TrustScope.Project, projectBPath);
			destVerifier.TrustedAssemblies.Count.ShouldBe(1);
			destVerifier.TrustedAssemblies.First().Name.ShouldBe("AssemblyA");
		}
	}
}
