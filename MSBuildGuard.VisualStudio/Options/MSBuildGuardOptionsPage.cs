using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.Shell;

namespace MSBuildGuard.VisualStudio.Options
{
	/// <summary>
	/// Represents the key management mode kinds.
	/// </summary>
	public enum KeyManagementModeKind
	{
		/// <summary>Mode is unconfigured.</summary>
		Unconfigured,

		/// <summary>Solo Developer mode using DPAPI.</summary>
		DPAPI,

		/// <summary>Team Environment mode using asymmetric certificates.</summary>
		Certificates
	}

	/// <summary>
	/// Represents persisted Visual Studio options placeholder for MSBuild Guard.
	/// Enables the Tools > Options tree node registration linked to Unified Settings.
	/// </summary>
	[Guid("a706a1c4-02be-4c9f-b6c8-1a95159ea9d2")]
	[ComVisible(true)]
	public sealed class MSBuildGuardOptionsPage : DialogPage
	{
		/// <summary>
		/// Defines the default list of file extensions to scan.
		/// </summary>
		private const string DefaultFileTypesToScan = ".csproj;.vbproj;.fsproj;.proj;.props;.targets;.sln;.slnx";

		/// <summary>
		/// Defines the default list of process creation indicators.
		/// </summary>
		private const string DefaultProcessCreationIndicators = "System.Diagnostics.Process;Process.Start(;CreateProcess(;cmd.exe;powershell;pwsh";

		/// <summary>
		/// Defines the default list of reflection and interop indicators.
		/// </summary>
		private const string DefaultReflectionInteropIndicators = "System.Reflection;Assembly.Load;Activator.CreateInstance;GetType(;dynamic ;DllImport;Marshal.GetDelegateForFunctionPointer;LoadLibrary";

		private bool allowSharingTrustsInRepositories;

		/// <summary>
		/// Gets or sets a value indicating whether security review windows should auto-open when a solution or project is opened.
		/// </summary>
		[Category("Behavior")]
		[DisplayName("Auto-open Security Review")]
		[Description("Automatically open Security Review when opening a solution or project.")]
		[DefaultValue(true)]
		public bool AutoOpenSecurityReviewOnOpen { get; set; } = true;

		/// <summary>
		/// Gets or sets a value indicating whether baseline onboarding setup is enabled.
		/// </summary>
		[Category("Behavior")]
		[DisplayName("Enable Baseline Onboarding")]
		[Description("Prompt to set up a trusted baseline when loading a new solution or project.")]
		[DefaultValue(true)]
		public bool EnableBaselineOnboarding { get; set; } = true;

		/// <summary>
		/// Gets or sets a value indicating whether NuGet package assets should be scanned.
		/// </summary>
		[Category("Scanning")]
		[DisplayName("Scan NuGet packages")]
		[Description("Include package-provided .props/.targets and related NuGet assets during scanning.")]
		[DefaultValue(true)]
		public bool ScanNuGetPackages { get; set; } = true;

		/// <summary>
		/// Gets or sets the key management mode used for signing and validating trust files.
		/// </summary>
		[Category("Trust Management")]
		[DisplayName("Key Management Mode")]
		[Description("Solo Developer (Local DPAPI) uses local machine keys, disabling repository sharing. Team Environment (Certificates) uses public/private certificate keys.")]
		[DefaultValue(KeyManagementModeKind.Unconfigured)]
		public KeyManagementModeKind KeyManagementMode { get; set; } = KeyManagementModeKind.Unconfigured;

		/// <summary>
		/// Gets or sets a value indicating whether strict asymmetric certificate-based signature verification is enforced.
		/// </summary>
		[Category("Trust Management")]
		[DisplayName("Enforce Asymmetric Signatures")]
		[Description("Strictly enforces asymmetric certificate-based signature verification for trust stores and policy documents.")]
		[DefaultValue(false)]
		public bool EnforceAsymmetricSignatures { get; set; }

		/// <summary>
		/// Gets or sets a value indicating whether trust files may be shared in repositories.
		/// </summary>
		[Category("Trust Management")]
		[DisplayName("Allow sharing trusts in repositories")]
		[Description("When enabled, MSBuild Guard removes managed .msbuildguard ignore entries from .gitignore files. When disabled, the entries are enforced.")]
		[DefaultValue(false)]
		public bool AllowSharingTrustsInRepositories
		{
			get
			{
				return allowSharingTrustsInRepositories;
			}
			set
			{
				if (KeyManagementMode == KeyManagementModeKind.DPAPI && value)
				{
					allowSharingTrustsInRepositories = false;

					return;
				}

				allowSharingTrustsInRepositories = value;
			}
		}

		/// <summary>
		/// Gets or sets a semicolon-separated list of file extensions to scan.
		/// </summary>
		[Category("Scanning")]
		[DisplayName("File types to scan")]
		[Description("Semicolon-separated file extensions, for example: .csproj;.targets;.props")]
		[DefaultValue(DefaultFileTypesToScan)]
		public string FileTypesToScan { get; set; } = DefaultFileTypesToScan;

		/// <summary>
		/// Gets or sets a semicolon-separated list of process creation indicators.
		/// </summary>
		[Category("Rule Indicators")]
		[DisplayName("Process creation indicators")]
		[Description("Semicolon-separated tokens used to detect process creation or shell execution in code/commands.")]
		[DefaultValue(DefaultProcessCreationIndicators)]
		public string ProcessCreationIndicators { get; set; } = DefaultProcessCreationIndicators;

		/// <summary>
		/// Gets or sets a semicolon-separated list of reflection or interop indicators.
		/// </summary>
		[Category("Rule Indicators")]
		[DisplayName("Reflection/interop indicators")]
		[Description("Semicolon-separated tokens used to detect reflection, dynamic loading, or native interop patterns.")]
		[DefaultValue(DefaultReflectionInteropIndicators)]
		public string ReflectionInteropIndicators { get; set; } = DefaultReflectionInteropIndicators;

		/// <summary>
		/// Gets or sets a semicolon-separated list of additional assemblies to block when referenced.
		/// </summary>
		[Category("Rule Indicators")]
		[DisplayName("Additional blocked assemblies")]
		[Description("Semicolon-separated assembly names that should be treated as blocked when referenced.")]
		[DefaultValue("")]
		public string AdditionalBlockedAssemblies { get; set; } = string.Empty;

		/// <inheritdoc/>
		protected override void OnApply(PageApplyEventArgs e)
		{
			base.OnApply(e);

			if (MSBuildGuardPackage.Instance != null)
			{
				MSBuildGuardPackage.Instance.NotifyOptionsChanged();

				ThreadHelper.JoinableTaskFactory.RunAsync(async delegate
				{
					await MSBuildGuardPackage.Instance.ApplyTrustSharingPreferenceAsync().ConfigureAwait(false);
				}).FileAndForget(nameof(MSBuildGuardOptionsPage));
			}
		}
	}
}
