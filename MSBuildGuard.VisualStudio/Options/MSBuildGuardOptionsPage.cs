using System.ComponentModel;
using System.Drawing.Design;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;

namespace MSBuildGuard.VisualStudio.Options
{
	/// <summary>
	/// Represents persisted Visual Studio options for MSBuild Guard.
	/// </summary>
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

		/// <summary>
		/// Defines the unified setting key for <see cref="AutoOpenSecurityReviewOnOpen"/>.
		/// </summary>
		internal const string AutoOpenSecurityReviewOnOpenSettingName = "extensions.msbuildguard.general.autoOpenSecurityReviewOnOpen";

		/// <summary>
		/// Defines the unified setting key for <see cref="ScanNuGetPackages"/>.
		/// </summary>
		internal const string ScanNuGetPackagesSettingName = "extensions.msbuildguard.general.scanNuGetPackages";

		/// <summary>
		/// Defines the unified setting key for <see cref="AllowSharingTrustsInRepositories"/>.
		/// </summary>
		internal const string AllowSharingTrustsInRepositoriesSettingName = "extensions.msbuildguard.trustManagement.allowSharingTrustsInRepositories";

		/// <summary>
		/// Defines the unified setting key for <see cref="FileTypesToScan"/>.
		/// </summary>
		internal const string FileTypesToScanSettingName = "extensions.msbuildguard.scanning.fileTypesToScan";

		/// <summary>
		/// Defines the unified setting key for <see cref="ProcessCreationIndicators"/>.
		/// </summary>
		internal const string ProcessCreationIndicatorsSettingName = "extensions.msbuildguard.ruleIndicators.processCreationIndicators";

		/// <summary>
		/// Defines the unified setting key for <see cref="ReflectionInteropIndicators"/>.
		/// </summary>
		internal const string ReflectionInteropIndicatorsSettingName = "extensions.msbuildguard.ruleIndicators.reflectionInteropIndicators";

		/// <summary>
		/// Defines the unified setting key for <see cref="AdditionalBlockedAssemblies"/>.
		/// </summary>
		internal const string AdditionalBlockedAssembliesSettingName = "extensions.msbuildguard.ruleIndicators.additionalBlockedAssemblies";

		/// <summary>
		/// Gets or sets a value indicating whether security review windows should auto-open when a solution or project is opened.
		/// </summary>
		[Category("Behavior")]
		[DisplayName("Auto-open Security Review")]
		[Description("Automatically open Security Review when opening a solution or project.")]
		[DefaultValue(true)]
		public bool AutoOpenSecurityReviewOnOpen { get; set; } = true;

		/// <summary>
		/// Gets or sets a value indicating whether NuGet package assets should be scanned.
		/// </summary>
		[Category("Scanning")]
		[DisplayName("Scan NuGet packages")]
		[Description("Include package-provided .props/.targets and related NuGet assets during scanning.")]
		[DefaultValue(true)]
		public bool ScanNuGetPackages { get; set; } = true;

		/// <summary>
		/// Gets or sets a value indicating whether trust files may be shared in repositories.
		/// </summary>
		[Category("Trust Management")]
		[DisplayName("Allow sharing trusts in repositories")]
		[Description("When enabled, MSBuild Guard removes managed .msbuildguard ignore entries from .gitignore files. When disabled, the entries are enforced.")]
		[DefaultValue(false)]
		public bool AllowSharingTrustsInRepositories { get; set; }

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

		/// <summary>
		/// Gets or sets the assembly trust management action.
		/// </summary>
		[Category("Trust Management")]
		[DisplayName("Manage assembly trusts")]
		[Description("Open the Manage Assembly Trusts dialog.")]
		[Editor(typeof(ManageAssemblyTrustsEditor), typeof(UITypeEditor))]
		public string ManageAssemblyTrustsAction { get; set; } = "Open...";

		/// <summary>
		/// Gets or sets the signer trust management action.
		/// </summary>
		[Category("Trust Management")]
		[DisplayName("Manage signer trusts")]
		[Description("Open the Manage Signer Trusts dialog.")]
		[Editor(typeof(ManageSignerTrustsEditor), typeof(UITypeEditor))]
		public string ManageSignerTrustsAction { get; set; } = "Open...";

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
