using System.ComponentModel;
using Microsoft.VisualStudio.Shell;

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
	}
}
