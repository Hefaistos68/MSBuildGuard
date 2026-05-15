using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
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
		/// The resolved path to an assembly file in the same package, or <paramref name="filePath"/> if no
		/// assembly can be found.
		/// </returns>
		public static string ResolveAssemblyFilePath(string filePath)
		{
			if (string.IsNullOrWhiteSpace(filePath))
			{
				return filePath;
			}

			if (IsAssemblyFile(filePath))
			{
				return filePath;
			}

			var packageRoot = FindPackageRoot(Path.GetDirectoryName(filePath));

			if (string.IsNullOrWhiteSpace(packageRoot))
			{
				return filePath;
			}

			var preferredName = Path.GetFileNameWithoutExtension(filePath);
			return FindBestAssemblyFile(packageRoot, preferredName);
		}

		/// <summary>
		/// Locates an assembly PE file in the NuGet global packages cache by package ID and version.
		/// </summary>
		/// <param name="packageId">NuGet package identifier (case-insensitive).</param>
		/// <param name="packageVersion">NuGet package version string.</param>
		/// <returns>
		/// The path to the best matching assembly in the package cache,
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
				".nuget",
				"packages",
				packageId.ToLowerInvariant(),
				packageVersion.ToLowerInvariant());

			if (!Directory.Exists(nugetCache))
			{
				return string.Empty;
			}

			return FindBestAssemblyFile(nugetCache, packageId);
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
				if (!TryReadEmbeddedCertificate(assemblyPath, out var certificate) || certificate == null)
				{
					return new AssemblySignatureInfo();
				}

				using var certificate2 = certificate;
				var signer = certificate2.GetNameInfo(X509NameType.SimpleName, false);

				if (string.IsNullOrWhiteSpace(signer))
				{
					signer = certificate2.Subject;
				}

				var signatureIsValid = VerifyAuthenticodeSignature(assemblyPath);

				return new AssemblySignatureInfo
				{
					HasEmbeddedSignature = true,
					IsSignatureValid     = signatureIsValid,
					IsSigned             = signatureIsValid,
					Signer               = signer ?? string.Empty,
					Issuer               = certificate2.Issuer ?? string.Empty,
					Subject              = certificate2.Subject ?? string.Empty,
					Thumbprint           = certificate2.Thumbprint ?? string.Empty,
					SerialNumber         = certificate2.SerialNumber ?? string.Empty
				};
			}
			catch
			{
				return new AssemblySignatureInfo();
			}
		}

		/// <summary>
		/// Verifies whether the file contains a readable embedded Authenticode certificate.
		/// </summary>
		/// <param name="assemblyPath">Assembly file path.</param>
		/// <param name="certificate">The extracted certificate when one is present.</param>
		/// <returns><see langword="true"/> when the file contains an embedded certificate; otherwise <see langword="false"/>.</returns>
		private static bool TryReadEmbeddedCertificate(string assemblyPath, out X509Certificate2? certificate)
		{
			certificate = null;

			try
			{
				var rawCertificate = X509Certificate.CreateFromSignedFile(assemblyPath);

				if (rawCertificate == null)
				{
					return false;
				}

				certificate = new X509Certificate2(rawCertificate);
				return true;
			}
			catch
			{
				certificate = null;
				return false;
			}
		}

		/// <summary>
		/// Verifies the file's Authenticode signature using the Windows trust provider.
		/// </summary>
		/// <param name="assemblyPath">Assembly file path.</param>
		/// <returns><see langword="true"/> when Windows reports the signature as valid; otherwise <see langword="false"/>.</returns>
		private static bool VerifyAuthenticodeSignature(string assemblyPath)
		{
			var fileInfo = new WinTrustFileInfo
			{
				CbStruct     = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo)),
				FilePath     = assemblyPath,
				FileHandle   = IntPtr.Zero,
				KnownSubject = IntPtr.Zero
			};

			var data = new WinTrustData
			{
				CbStruct           = (uint)Marshal.SizeOf(typeof(WinTrustData)),
				PolicyCallbackData = IntPtr.Zero,
				SipClientData      = IntPtr.Zero,
				UiChoice           = WinTrustUiChoiceNone,
				RevocationChecks   = WinTrustRevocationChecksNone,
				UnionChoice        = WinTrustDataChoiceFile,
				FileInfoPointer    = IntPtr.Zero,
				StateAction        = WinTrustStateActionNone,
				StateData          = IntPtr.Zero,
				UrlReference       = null,
				ProvFlags          = WinTrustProvFlagsHashOnly,
				UiContext          = 0,
				SignatureSettings  = IntPtr.Zero
			};

			var fileInfoPointer = IntPtr.Zero;

			try
			{
				fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
				Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
				data.FileInfoPointer = fileInfoPointer;

				var result = WinVerifyTrust(IntPtr.Zero, WinTrustActionGenericVerifyV2, ref data);
				return result == 0;
			}
			catch
			{
				return false;
			}
			finally
			{
				if (fileInfoPointer != IntPtr.Zero)
				{
					Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
					Marshal.FreeHGlobal(fileInfoPointer);
				}
			}
		}

		private static bool IsAssemblyFile(string filePath)
		{
			var extension = Path.GetExtension(filePath);

			return string.Equals(extension, ".dll", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(extension, ".exe", StringComparison.OrdinalIgnoreCase);
		}

		[DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = false)]
		private static extern int WinVerifyTrust(IntPtr hwnd, Guid pgActionID, ref WinTrustData pWVTData);

		private static readonly Guid WinTrustActionGenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

		private const uint WinTrustDataChoiceFile     = 1;
		private const uint WinTrustUiChoiceNone      = 2;
		private const uint WinTrustRevocationChecksNone = 0;
		private const uint WinTrustStateActionNone    = 0;
		private const uint WinTrustProvFlagsHashOnly  = 0x00000200;

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		private struct WinTrustFileInfo
		{
			public uint CbStruct;

			[MarshalAs(UnmanagedType.LPWStr)]
			public string FilePath;

			public IntPtr FileHandle;
			public IntPtr KnownSubject;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		private struct WinTrustData
		{
			public uint CbStruct;
			public IntPtr PolicyCallbackData;
			public IntPtr SipClientData;
			public uint UiChoice;
			public uint RevocationChecks;
			public uint UnionChoice;
			public IntPtr FileInfoPointer;
			public uint StateAction;
			public IntPtr StateData;

			[MarshalAs(UnmanagedType.LPWStr)]
			public string? UrlReference;

			public uint ProvFlags;
			public uint UiContext;
			public IntPtr SignatureSettings;
		}

		private static string FindPackageRoot(string? startDirectory)
		{
			var candidate = startDirectory;

			for (var depth = 0; depth < 6 && !string.IsNullOrWhiteSpace(candidate) && Directory.Exists(candidate); depth++)
			{
				if (Directory.Exists(Path.Combine(candidate, "lib")) ||
					Directory.Exists(Path.Combine(candidate, "tools")) ||
					Directory.Exists(Path.Combine(candidate, "runtimes")))
				{
					return candidate;
				}

				candidate = Path.GetDirectoryName(candidate);
			}

			return string.Empty;
		}

		private static string FindBestAssemblyFile(string packageRoot, string preferredName)
		{
			var preferredMatches = Directory
				.GetFiles(packageRoot, "*.dll", SearchOption.AllDirectories)
				.Concat(Directory.GetFiles(packageRoot, "*.exe", SearchOption.AllDirectories))
				.Where(path => !path.EndsWith(".resources.dll", StringComparison.OrdinalIgnoreCase))
				.Where(path => string.Equals(Path.GetFileNameWithoutExtension(path), preferredName, StringComparison.OrdinalIgnoreCase))
				.OrderBy(path => AssemblyFileRank(path))
				.ToList();

			if (preferredMatches.Count > 0)
			{
				return preferredMatches[0];
			}

			var anyMatches = Directory
				.GetFiles(packageRoot, "*.dll", SearchOption.AllDirectories)
				.Concat(Directory.GetFiles(packageRoot, "*.exe", SearchOption.AllDirectories))
				.Where(path => !path.EndsWith(".resources.dll", StringComparison.OrdinalIgnoreCase))
				.OrderBy(path => AssemblyFileRank(path))
				.ToList();

			if (anyMatches.Count > 0)
			{
				return anyMatches[0];
			}

			return string.Empty;
		}

		private static int AssemblyFileRank(string path)
		{
			var normalized = path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

			if (normalized.IndexOf(Path.DirectorySeparatorChar + "lib" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0)
			{
				return 0;
			}

			if (normalized.IndexOf(Path.DirectorySeparatorChar + "tools" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0)
			{
				return 1;
			}

			if (normalized.IndexOf(Path.DirectorySeparatorChar + "runtimes" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) >= 0)
			{
				return 2;
			}

			return 3;
		}

	}

	/// <summary>
	/// Represents assembly signature identity fields extracted from Authenticode metadata.
	/// </summary>
	internal sealed class AssemblySignatureInfo
	{
		/// <summary>
		/// Gets or sets a value indicating whether the file has an embedded signature blob.
		/// </summary>
		public bool HasEmbeddedSignature { get; set; }

		/// <summary>
		/// Gets or sets a value indicating whether the Authenticode signature is valid.
		/// </summary>
		public bool IsSignatureValid { get; set; }

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

		/// <summary>
		/// Gets or sets the certificate thumbprint.
		/// </summary>
		public string Thumbprint { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets the certificate serial number.
		/// </summary>
		public string SerialNumber { get; set; } = string.Empty;

		/// <summary>
		/// Gets or sets a value indicating whether the signature is valid. Use <see cref="IsSignatureValid"/> instead.
		/// </summary>
		[Obsolete("Use HasEmbeddedSignature and IsSignatureValid instead.")]
		public bool IsSigned
		{
			get
			{
				return this.IsSignatureValid;
			}
			set
			{
				this.IsSignatureValid = value;
			}
		}
	}
}
