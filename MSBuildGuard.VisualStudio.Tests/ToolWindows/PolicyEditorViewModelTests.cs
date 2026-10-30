using System;
using System.IO;
using MSBuildGuard.Core;
using MSBuildGuard.Core.Policy;
using MSBuildGuard.VisualStudio.ToolWindows;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.VisualStudio.ToolWindows.Tests
{
	/// <summary>
	/// Unit tests for the <see cref="PolicyEditorViewModel"/> class.
	/// </summary>
	[TestFixture]
	public sealed class PolicyEditorViewModelTests
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
		/// Verifies that <see cref="PolicyEditorViewModel.Save"/> preserves existing rules, include/exclude patterns, and package source lists from a loaded policy document.
		/// </summary>
		[Test]
		public void Save_WhenPolicyDocumentLoaded_PreservesExistingCollectionsAndRules()
		{
			var solutionPath = Path.Combine(this.tempDir, "TestSolution.sln");
			var policyDir    = Path.Combine(this.tempDir, ".msbuildguard");
			var policyPath   = Path.Combine(policyDir, "policy.json");

			File.WriteAllText(solutionPath, string.Empty);
			Directory.CreateDirectory(policyDir);

			var policyService   = new PolicyService();
			var initialDocument = policyService.CreateDefault();

			initialDocument.Version    = 2;
			initialDocument.Mode       = "warn";
			initialDocument.StrictMode = false;
			initialDocument.Rules["MBG999"] = new PolicyRuleSetting
			{
				Action = PolicyAction.Block
			};
			initialDocument.Include.Add("src/**/*.csproj");
			initialDocument.Exclude.Add("tests/**/*.csproj");
			initialDocument.AllowedPackageSources.Add("https://api.nuget.org/v3/index.json");
			initialDocument.BlockedPackageSources.Add("https://untrusted.example.com/v3/index.json");

			policyService.Save(policyPath, initialDocument);

			var viewModel = new PolicyEditorViewModel();

			viewModel.LoadContext(solutionPath, Array.Empty<string>(), PolicyEditorViewModel.PolicyScopeType.Solution);
			viewModel.StrictMode = true;
			viewModel.Save();

			var reloaded = policyService.LoadUnsigned(policyPath);

			reloaded.StrictMode.ShouldBeTrue();
			reloaded.Version.ShouldBe(2);
			reloaded.Mode.ShouldBe("warn");
			reloaded.Rules.ContainsKey("MBG999").ShouldBeTrue();
			reloaded.Rules["MBG999"].Action.ShouldBe(PolicyAction.Block);
			reloaded.Include.ShouldContain("src/**/*.csproj");
			reloaded.Exclude.ShouldContain("tests/**/*.csproj");
			reloaded.AllowedPackageSources.ShouldContain("https://api.nuget.org/v3/index.json");
			reloaded.BlockedPackageSources.ShouldContain("https://untrusted.example.com/v3/index.json");
			viewModel.IsDirty.ShouldBeFalse();
		}
	}
}
