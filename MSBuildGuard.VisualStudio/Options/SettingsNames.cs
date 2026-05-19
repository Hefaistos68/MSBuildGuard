namespace MSBuildGuard.VisualStudio.Options
{
	/// <summary>
	/// Defines unified-setting keys and legacy registry paths for MSBuild Guard options.
	/// </summary>
	internal static class SettingsNames
	{
		/// <summary>
		/// Gets the auto-open security review setting metadata.
		/// </summary>
		internal static SettingName AutoOpenSecurityReviewOnOpen { get; } = new(
			"extensions.msbuildguard.general.autoOpenSecurityReviewOnOpen",
			"MSBuild Guard\\General\\AutoOpenSecurityReviewOnOpen");

		/// <summary>
		/// Gets the scan NuGet packages setting metadata.
		/// </summary>
		internal static SettingName ScanNuGetPackages { get; } = new(
			"extensions.msbuildguard.general.scanNuGetPackages",
			"MSBuild Guard\\General\\ScanNuGetPackages");

		/// <summary>
		/// Gets the allow sharing trusts in repositories setting metadata.
		/// </summary>
		internal static SettingName AllowSharingTrustsInRepositories { get; } = new(
			"extensions.msbuildguard.trustManagement.allowSharingTrustsInRepositories",
			"MSBuild Guard\\General\\AllowSharingTrustsInRepositories");

		/// <summary>
		/// Gets the file types to scan setting metadata.
		/// </summary>
		internal static SettingName FileTypesToScan { get; } = new(
			"extensions.msbuildguard.scanning.fileTypesToScan",
			"MSBuild Guard\\General\\FileTypesToScan");

		/// <summary>
		/// Gets the process creation indicators setting metadata.
		/// </summary>
		internal static SettingName ProcessCreationIndicators { get; } = new(
			"extensions.msbuildguard.ruleIndicators.processCreationIndicators",
			"MSBuild Guard\\General\\ProcessCreationIndicators");

		/// <summary>
		/// Gets the reflection and interop indicators setting metadata.
		/// </summary>
		internal static SettingName ReflectionInteropIndicators { get; } = new(
			"extensions.msbuildguard.ruleIndicators.reflectionInteropIndicators",
			"MSBuild Guard\\General\\ReflectionInteropIndicators");

		/// <summary>
		/// Gets the additional blocked assemblies setting metadata.
		/// </summary>
		internal static SettingName AdditionalBlockedAssemblies { get; } = new(
			"extensions.msbuildguard.ruleIndicators.additionalBlockedAssemblies",
			"MSBuild Guard\\General\\AdditionalBlockedAssemblies");
	}

	/// <summary>
	/// Represents the unified key and legacy registry path for a setting.
	/// </summary>
	internal sealed class SettingName
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="SettingName"/> class.
		/// </summary>
		/// <param name="unifiedName">Unified settings key.</param>
		/// <param name="legacyName">Legacy settings registry path.</param>
		internal SettingName(string unifiedName, string legacyName)
		{
			this.UnifiedName = unifiedName;
			this.LegacyName = legacyName;
		}

		/// <summary>
		/// Gets the unified settings key.
		/// </summary>
		internal string UnifiedName { get; private set; }

		/// <summary>
		/// Gets the legacy settings registry path.
		/// </summary>
		internal string LegacyName { get; private set; }
	}
}
