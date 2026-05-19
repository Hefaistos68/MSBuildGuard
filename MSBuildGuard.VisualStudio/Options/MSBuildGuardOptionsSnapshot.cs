namespace MSBuildGuard.VisualStudio.Options
{
	/// <summary>
	/// Represents a runtime snapshot of MSBuild Guard option values.
	/// </summary>
	internal sealed class MSBuildGuardOptionsSnapshot
	{
		/// <summary>
		/// Gets or sets a value indicating whether security review auto-open is enabled.
		/// </summary>
		internal bool AutoOpenSecurityReviewOnOpen { get; set; } = true;

		/// <summary>
		/// Gets or sets a value indicating whether NuGet package scanning is enabled.
		/// </summary>
		internal bool ScanNuGetPackages { get; set; } = true;

		/// <summary>
		/// Gets or sets a value indicating whether trust sharing in repositories is enabled.
		/// </summary>
		internal bool AllowSharingTrustsInRepositories { get; set; }

		/// <summary>
		/// Gets or sets a semicolon-separated list of file types to scan.
		/// </summary>
		internal string FileTypesToScan { get; set; } = ".csproj;.vbproj;.fsproj;.proj;.props;.targets;.sln;.slnx";

		/// <summary>
		/// Gets or sets a semicolon-separated list of process creation indicators.
		/// </summary>
		internal string ProcessCreationIndicators { get; set; } = "System.Diagnostics.Process;Process.Start(;CreateProcess(;cmd.exe;powershell;pwsh";

		/// <summary>
		/// Gets or sets a semicolon-separated list of reflection/interop indicators.
		/// </summary>
		internal string ReflectionInteropIndicators { get; set; } = "System.Reflection;Assembly.Load;Activator.CreateInstance;GetType(;dynamic ;DllImport;Marshal.GetDelegateForFunctionPointer;LoadLibrary";

		/// <summary>
		/// Gets or sets a semicolon-separated list of additional blocked assemblies.
		/// </summary>
		internal string AdditionalBlockedAssemblies { get; set; } = string.Empty;
	}
}
