using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Resolves solution and repository context from Visual Studio.
	/// </summary>
	internal sealed class SolutionDiscoveryService
	{
		/// <summary>
		/// Gets a value indicating whether a solution is currently loaded.
		/// </summary>
		/// <returns><c>true</c> when a valid solution path is loaded; otherwise <c>false</c>.</returns>
		public static bool HasOpenSolution()
		{
			ThreadHelper.ThrowIfNotOnUIThread();

			var solution = Package.GetGlobalService(typeof(SVsSolution)) as IVsSolution;

			if (solution == null)
			{
				return false;
			}

			solution.GetSolutionInfo(out _, out var solutionPath, out _);

			return !string.IsNullOrWhiteSpace(solutionPath) && File.Exists(solutionPath);
		}

		/// <summary>
		/// Gets the currently opened solution full path.
		/// </summary>
		/// <param name="package">Owning package.</param>
		/// <returns>The solution full path or null when not available.</returns>
		public static async Task<string?> GetOpenSolutionPathAsync(AsyncPackage package)
		{
			await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

			var solution = await package.GetServiceAsync(typeof(SVsSolution)) as IVsSolution;

			if (solution == null)
			{
				return null;
			}

			solution.GetSolutionInfo(out _, out var solutionPath, out _);

			if (string.IsNullOrWhiteSpace(solutionPath))
			{
				return null;
			}

			return solutionPath;
		}

		/// <summary>
		/// Attempts to find the repository root by walking parents and locating a .git folder.
		/// </summary>
		/// <param name="solutionPath">The current solution path.</param>
		/// <returns>The repository root path or null.</returns>
		public static string? TryResolveRepositoryRoot(string? solutionPath)
		{
			if (string.IsNullOrWhiteSpace(solutionPath))
			{
				return null;
			}

			var current = new DirectoryInfo(Path.GetDirectoryName(solutionPath) ?? string.Empty);

			while (current != null)
			{
				var gitPath = Path.Combine(current.FullName, ".git");

				if (Directory.Exists(gitPath) || File.Exists(gitPath))
				{
					return current.FullName;
				}

				current = current.Parent;
			}

			return null;
		}
	}
}
