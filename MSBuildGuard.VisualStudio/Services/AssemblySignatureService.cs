using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Provides Authenticode signature inspection for assembly files.
	/// </summary>
	internal sealed class AssemblySignatureService
	{
		/// <summary>
		/// Resolves the path to an actual PE assembly file (.dll or .exe) given a file path that may
		/// point to a non-PE build artifact (e.g., a <c>.targets</c> or <c>.props</c> file inside a
		/// NuGet package). When the input path already points to a PE file it is returned unchanged.
		/// </summary>
		/// <param name="filePath">Source file path, which may be any file inside a NuGet package directory.</param>
		/// <returns>
		/// The resolved path to a <c>.dll</c> file in the same package, or <paramref name="filePath"/> if no
		/// assembly can be found.
		/// </returns>
		public static string ResolveAssemblyFilePath(string filePath)
		{
			if (string.IsNullOrWhiteSpace(filePath))
			{
				return filePath;
			}

			var extension = Path.GetExtension(filePath).ToLowerInvariant();

			if (extension == ".dll" || extension == ".exe")
			{
				return filePath;
			}

			// Walk up from the file's directory, up to 4 levels, looking for the NuGet package
			// root — identified by the presence of a lib\ subdirectory.
			// A .targets file can be nested: build\pkg.targets (1 level) or
			// build\net472\pkg.targets (2 levels), so a fixed single-level walk is insufficient.
			var candidate = Path.GetDirectoryName(filePath);

			for (var depth = 0; depth < 4 && !string.IsNullOrWhiteSpace(candidate) && Directory.Exists(candidate); depth++)
			{
				var libDir = Path.Combine(candidate, "lib");

				if (Directory.Exists(libDir))
				{
					var libDlls = Directory.GetFiles(libDir, "*.dll", SearchOption.AllDirectories);

					if (libDlls.Length > 0)
					{
						return libDlls[0];
					}
				}

					candidate = Path.GetDirectoryName(candidate);
					}

					return filePath;
				}

				/// <summary>
				/// Locates an assembly PE file in the NuGet global packages cache by package ID and version.
				/// </summary>
				/// <param name="packageId">NuGet package identifier (case-insensitive).</param>
				/// <param name="packageVersion">NuGet package version string.</param>
				/// <returns>
				/// The path to the first <c>.dll</c> found in the package's <c>lib\</c> directory,
				/// or an empty string if the package is not present in the cache.
				/// </returns>
				public static string ResolveAssemblyFilePathFromPackageId(string packageId, string packageVersion)
				{
					if (string.IsNullOrWhiteSpace(packageId) || string.IsNullOrWhiteSpace(packageVersion))
					{
						return string.Empty;
					}

					var nugetCache = Path.Combine(
						Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
						".nuget", "packages",
						packageId.ToLowerInvariant(),
						packageVersion.ToLowerInvariant());

					if (!Directory.Exists(nugetCache))
					{
						return string.Empty;
					}

					var libDir = Path.Combine(nugetCache, "lib");

					if (Directory.Exists(libDir))
					{
						var libDlls = Directory.GetFiles(libDir, "*.dll", SearchOption.AllDirectories);

						if (libDlls.Length > 0)
						{
							return libDlls[0];
						}
					}

					return string.Empty;
				}

				/// <summary>
				/// Reads Authenticode signature details from the specified assembly file.
				/// </summary>
				/// <param name="assemblyPath">Assembly file path.</param>
				/// <returns>The extracted signature details.</returns>
				public AssemblySignatureInfo ReadSignature(string assemblyPath)
				{
					if (string.IsNullOrWhiteSpace(assemblyPath) || !File.Exists(assemblyPath))
					{
						return new AssemblySignatureInfo();
					}

					try
					{
				var certificate = X509Certificate.CreateFromSignedFile(assemblyPath);

				if (certificate == null)
				{
					return new AssemblySignatureInfo();
				}

				using var certificate2 = new X509Certificate2(certificate);
				var signer = certificate2.GetNameInfo(X509NameType.SimpleName, false);

				if (string.IsNullOrWhiteSpace(signer))
				{
					signer = certificate2.Subject;
				}

				return new AssemblySignatureInfo
				{
					IsSigned = true,
					Signer = signer ?? string.Empty,
					Issuer = certificate2.Issuer ?? string.Empty,
					Subject = certificate2.Subject ?? string.Empty
				};
			}
			catch
			{
				return new AssemblySignatureInfo();
			}
		}
	}

	/// <summary>
	/// Represents assembly signature identity fields extracted from Authenticode metadata.
	/// </summary>
	internal sealed class AssemblySignatureInfo
	{
		/// <summary>
		/// Gets or sets a value indicating whether the assembly is Authenticode signed.
		/// </summary>
		public bool IsSigned { get; set; }

		/// <summary>
		/// Gets or sets the signer display name.
		/// </summary>
		public string Signer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the certificate issuer.
		/// </summary>
		public string Issuer { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the certificate subject.
		/// </summary>
		public string Subject { get; set; } = string.Empty;
	}
}
