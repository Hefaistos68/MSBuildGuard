using System;
using System.IO;
using MSBuildGuard.Core.Policy;

namespace MSBuildGuard.Worker
{
	/// <summary>
	/// Resolves effective policy information by loading and merging policies across scopes.
	/// </summary>
	public sealed class PolicyStatusService
	{
		private readonly PolicyService policyService;

		/// <summary>
		/// Initializes a new instance of the <see cref="PolicyStatusService"/> class.
		/// </summary>
		public PolicyStatusService()
		{
			this.policyService = new PolicyService();
		}

		/// <summary>
		/// Loads and merges machine, repository/project, and user policy documents.
		/// </summary>
		/// <param name="repositoryRoot">Repository root path.</param>
		/// <param name="scanTargetPath">Optional scan target path used to resolve project-specific policies.</param>
		/// <returns>The effective policy document.</returns>
		public PolicyDocument GetEffectivePolicy(string? repositoryRoot, string? scanTargetPath)
		{
			try
			{
				var machinePolicyPath = this.policyService.GetMachinePolicyPath();
				var userPolicyPath = this.policyService.GetUserPolicyPath();
				var policyPath = string.Empty;

				if (!string.IsNullOrWhiteSpace(repositoryRoot))
				{
					policyPath = this.policyService.GetRepositoryPolicyPath(repositoryRoot!);
				}

				if (IsProjectFilePath(scanTargetPath))
				{
					var projectPolicyPath = this.policyService.GetProjectPolicyPath(scanTargetPath!);

					if (File.Exists(projectPolicyPath))
					{
						policyPath = projectPolicyPath;
					}
				}

				var machinePolicy = TryLoadPolicy(machinePolicyPath);
				var repository = string.IsNullOrWhiteSpace(policyPath) ? null : TryLoadPolicy(policyPath);
				var userPolicy = TryLoadPolicy(userPolicyPath);
				var defaults = this.policyService.CreateDefault();
				var merged = this.policyService.Merge(machinePolicy, repository, userPolicy, defaults);

				return merged;
			}
			catch (Exception)
			{
				return this.policyService.CreateFailSafeBlockPolicy();
			}
		}

		/// <summary>
		/// Determines whether the specified path points to a C# (.csproj), VB (.vbproj), or F# (.fsproj) project file.
		/// </summary>
		/// <param name="path">The file path to evaluate.</param>
		/// <returns><c>true</c> if the path has a project file extension; otherwise, <c>false</c>.</returns>
		private static bool IsProjectFilePath(string? path)
		{
			if (string.IsNullOrWhiteSpace(path))
			{
				return false;
			}

			var extension = Path.GetExtension(path);

			if (string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			if (string.Equals(extension, ".vbproj", StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			if (string.Equals(extension, ".fsproj", StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			return false;
		}

		/// <summary>
		/// Attempts to load and parse a policy document from the specified file path if it exists.
		/// </summary>
		/// <param name="policyPath">The path to the policy file.</param>
		/// <returns>The loaded <see cref="PolicyDocument"/> if found; otherwise, <c>null</c>.</returns>
		private PolicyDocument? TryLoadPolicy(string policyPath)
		{
			if (string.IsNullOrWhiteSpace(policyPath) || !File.Exists(policyPath))
			{
				return null;
			}

			var document = this.policyService.Load(policyPath);

			return document;
		}
	}
}
