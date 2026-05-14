using System;
using System.IO;
using MSBuildGuard.Core.Policy;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Resolves effective policy information for display in Visual Studio.
	/// </summary>
	internal sealed class PolicyStatusService
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

			return this.policyService.Merge(machinePolicy, repository, userPolicy, defaults);
		}

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
		/// Loads policy if the file exists.
		/// </summary>
		/// <param name="policyPath">Path to policy file.</param>
		/// <returns>Policy document or null.</returns>
		private PolicyDocument? TryLoadPolicy(string policyPath)
		{
			if (string.IsNullOrWhiteSpace(policyPath) || !File.Exists(policyPath))
			{
				return null;
			}

			return this.policyService.Load(policyPath);
		}
	}
}
