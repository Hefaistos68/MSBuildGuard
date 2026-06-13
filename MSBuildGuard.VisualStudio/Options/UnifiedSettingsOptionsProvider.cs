using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Settings;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Settings;
using Microsoft.VisualStudio.Threading;

namespace MSBuildGuard.VisualStudio.Options
{
	/// <summary>
	/// Reads MSBuild Guard option values from Visual Studio unified settings storage with legacy fallback.
	/// Uses a Razor-like storage pattern with async initialization, cached snapshots, and change notification.
	/// </summary>
	internal sealed class UnifiedSettingsOptionsProvider : IDisposable
	{
		private JoinableTask? initializeTask;
		private MSBuildGuardOptionsSnapshot? currentSnapshot;

		/// <summary>
		/// Raised when the effective options snapshot changes.
		/// </summary>
		internal event Action? Changed;

		/// <summary>
		/// Loads the current options snapshot from settings storage.
		/// </summary>
		/// <param name="package">Owning package instance.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>The resolved options snapshot.</returns>
		internal async Task<MSBuildGuardOptionsSnapshot> GetSnapshotAsync(AsyncPackage package, CancellationToken cancellationToken)
		{
			await EnsureInitializedAsync(package, cancellationToken).ConfigureAwait(false);
			await package.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

			var snapshot = ReadSnapshot(package);

			if (this.currentSnapshot == null || !AreEquivalent(this.currentSnapshot, snapshot))
			{
				this.currentSnapshot = snapshot;
				this.Changed?.Invoke();
			}

			return snapshot;
		}

		/// <summary>
		/// Notifies storage that options were updated externally and invalidates cached state.
		/// </summary>
		internal void NotifyChanged()
		{
			this.currentSnapshot = null;
			this.Changed?.Invoke();
		}

		private async Task EnsureInitializedAsync(AsyncPackage package, CancellationToken cancellationToken)
		{
			if (this.initializeTask == null)
			{
				this.initializeTask = package.JoinableTaskFactory.RunAsync(async delegate
				{
					await package.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);
				});
			}

			await this.initializeTask.Task.ConfigureAwait(false);
		}

		private static MSBuildGuardOptionsSnapshot ReadSnapshot(AsyncPackage package)
		{
			var snapshot = new MSBuildGuardOptionsSnapshot();
			var settingsManager = new ShellSettingsManager(package);
			var store = settingsManager.GetReadOnlySettingsStore(SettingsScope.UserSettings);

			snapshot.AutoOpenSecurityReviewOnOpen = ReadBoolean(store, SettingsNames.AutoOpenSecurityReviewOnOpen, snapshot.AutoOpenSecurityReviewOnOpen);
			snapshot.EnableBaselineOnboarding = ReadBoolean(store, SettingsNames.EnableBaselineOnboarding, snapshot.EnableBaselineOnboarding);
			snapshot.ScanNuGetPackages = ReadBoolean(store, SettingsNames.ScanNuGetPackages, snapshot.ScanNuGetPackages);
			snapshot.AllowSharingTrustsInRepositories = ReadBoolean(store, SettingsNames.AllowSharingTrustsInRepositories, snapshot.AllowSharingTrustsInRepositories);
			snapshot.FileTypesToScan = ReadString(store, SettingsNames.FileTypesToScan, snapshot.FileTypesToScan);
			snapshot.ProcessCreationIndicators = ReadString(store, SettingsNames.ProcessCreationIndicators, snapshot.ProcessCreationIndicators);
			snapshot.ReflectionInteropIndicators = ReadString(store, SettingsNames.ReflectionInteropIndicators, snapshot.ReflectionInteropIndicators);
			snapshot.AdditionalBlockedAssemblies = ReadString(store, SettingsNames.AdditionalBlockedAssemblies, snapshot.AdditionalBlockedAssemblies);

			return snapshot;
		}

		private static bool AreEquivalent(MSBuildGuardOptionsSnapshot left, MSBuildGuardOptionsSnapshot right)
		{
			return left.AutoOpenSecurityReviewOnOpen == right.AutoOpenSecurityReviewOnOpen &&
				left.EnableBaselineOnboarding == right.EnableBaselineOnboarding &&
				left.ScanNuGetPackages == right.ScanNuGetPackages &&
				left.AllowSharingTrustsInRepositories == right.AllowSharingTrustsInRepositories &&
				string.Equals(left.FileTypesToScan, right.FileTypesToScan, StringComparison.Ordinal) &&
				string.Equals(left.ProcessCreationIndicators, right.ProcessCreationIndicators, StringComparison.Ordinal) &&
				string.Equals(left.ReflectionInteropIndicators, right.ReflectionInteropIndicators, StringComparison.Ordinal) &&
				string.Equals(left.AdditionalBlockedAssemblies, right.AdditionalBlockedAssemblies, StringComparison.Ordinal);
		}

		/// <summary>
		/// Reads a boolean setting with unified-key first and legacy-path fallback semantics.
		/// </summary>
		/// <param name="store">Settings store.</param>
		/// <param name="settingName">Unified and legacy setting identifiers.</param>
		/// <param name="defaultValue">Default value when no setting exists.</param>
		/// <returns>The resolved boolean setting value.</returns>
		private static bool ReadBoolean(SettingsStore store, SettingName settingName, bool defaultValue)
		{
			if (TrySplitUnifiedKey(settingName.UnifiedName, out var unifiedCollection, out var unifiedProperty) &&
				TryReadBoolean(store, unifiedCollection, unifiedProperty, out var unifiedValue))
			{
				return unifiedValue;
			}

			if (TrySplitLegacyPath(settingName.LegacyName, out var legacyCollection, out var legacyProperty) &&
				TryReadBoolean(store, legacyCollection, legacyProperty, out var legacyValue))
			{
				return legacyValue;
			}

			return defaultValue;
		}

		/// <summary>
		/// Reads a string setting with unified-key first and legacy-path fallback semantics.
		/// </summary>
		/// <param name="store">Settings store.</param>
		/// <param name="settingName">Unified and legacy setting identifiers.</param>
		/// <param name="defaultValue">Default value when no setting exists.</param>
		/// <returns>The resolved string setting value.</returns>
		private static string ReadString(SettingsStore store, SettingName settingName, string defaultValue)
		{
			if (TrySplitUnifiedKey(settingName.UnifiedName, out var unifiedCollection, out var unifiedProperty) &&
				TryReadString(store, unifiedCollection, unifiedProperty, out var unifiedValue))
			{
				return unifiedValue;
			}

			if (TrySplitLegacyPath(settingName.LegacyName, out var legacyCollection, out var legacyProperty) &&
				TryReadString(store, legacyCollection, legacyProperty, out var legacyValue))
			{
				return legacyValue;
			}

			return defaultValue;
		}

		/// <summary>
		/// Attempts to parse a unified setting key into settings-store collection and property names.
		/// </summary>
		/// <param name="unifiedName">Unified setting key.</param>
		/// <param name="collection">Resolved collection path.</param>
		/// <param name="property">Resolved property name.</param>
		/// <returns><c>true</c> when parsing succeeded; otherwise <c>false</c>.</returns>
		private static bool TrySplitUnifiedKey(string unifiedName, out string collection, out string property)
		{
			collection = string.Empty;
			property = string.Empty;

			if (string.IsNullOrWhiteSpace(unifiedName))
			{
				return false;
			}

			var separatorIndex = unifiedName.LastIndexOf('.');

			if (separatorIndex <= 0 || separatorIndex >= unifiedName.Length - 1)
			{
				return false;
			}

			collection = unifiedName.Substring(0, separatorIndex);
			property = unifiedName.Substring(separatorIndex + 1);

			return true;
		}

		/// <summary>
		/// Attempts to parse a legacy settings path into settings-store collection and property names.
		/// </summary>
		/// <param name="legacyName">Legacy settings path.</param>
		/// <param name="collection">Resolved collection path.</param>
		/// <param name="property">Resolved property name.</param>
		/// <returns><c>true</c> when parsing succeeded; otherwise <c>false</c>.</returns>
		private static bool TrySplitLegacyPath(string legacyName, out string collection, out string property)
		{
			collection = string.Empty;
			property = string.Empty;

			if (string.IsNullOrWhiteSpace(legacyName))
			{
				return false;
			}

			var separatorIndex = legacyName.LastIndexOf('\\');

			if (separatorIndex <= 0 || separatorIndex >= legacyName.Length - 1)
			{
				return false;
			}

			collection = legacyName.Substring(0, separatorIndex);
			property = legacyName.Substring(separatorIndex + 1);

			return true;
		}

		/// <summary>
		/// Attempts to read a boolean property from a settings-store collection.
		/// </summary>
		/// <param name="store">Settings store.</param>
		/// <param name="collection">Collection path.</param>
		/// <param name="property">Property name.</param>
		/// <param name="value">Resolved value.</param>
		/// <returns><c>true</c> when value was found and read; otherwise <c>false</c>.</returns>
		private static bool TryReadBoolean(SettingsStore store, string collection, string property, out bool value)
		{
			value = false;

			if (!store.CollectionExists(collection) || !store.PropertyExists(collection, property))
			{
				return false;
			}

			value = store.GetBoolean(collection, property, false);

			return true;
		}

		/// <summary>
		/// Attempts to read a string property from a settings-store collection.
		/// </summary>
		/// <param name="store">Settings store.</param>
		/// <param name="collection">Collection path.</param>
		/// <param name="property">Property name.</param>
		/// <param name="value">Resolved value.</param>
		/// <returns><c>true</c> when value was found and read; otherwise <c>false</c>.</returns>
		private static bool TryReadString(SettingsStore store, string collection, string property, out string value)
		{
			value = string.Empty;

			if (!store.CollectionExists(collection) || !store.PropertyExists(collection, property))
			{
				return false;
			}

			value = store.GetString(collection, property, string.Empty);

			return true;
		}

		/// <inheritdoc/>
		public void Dispose()
		{
			this.initializeTask = null;
			this.currentSnapshot = null;
			this.Changed = null;
		}
	}
}
