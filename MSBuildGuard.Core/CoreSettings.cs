using System;

namespace MSBuildGuard.Core
{
	/// <summary>
	/// Provides static configuration settings for MSBuildGuard core services.
	/// </summary>
	public static class CoreSettings
	{
		/// <summary>
		/// Gets or sets a value indicating whether asymmetric certificate-based signature verification is strictly enforced.
		/// </summary>
		public static bool EnforceAsymmetricSignatures { get; set; }

		/// <summary>
		/// Gets or sets a value indicating whether sharing trusts in repositories is allowed.
		/// </summary>
		public static bool AllowSharingTrustsInRepositories { get; set; }
	}
}
