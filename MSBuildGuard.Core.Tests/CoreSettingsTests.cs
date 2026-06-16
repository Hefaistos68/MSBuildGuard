using System;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Tests
{
	/// <summary>
	/// Tests for <see cref="CoreSettings"/>.
	/// </summary>
	[TestFixture]
	public sealed class CoreSettingsTests
	{
		/// <summary>
		/// Verifies that CoreSettings properties can be set and get successfully.
		/// </summary>
		[Test]
		public void CoreSettings_ShouldSetAndGetProperties()
		{
			CoreSettings.EnforceAsymmetricSignatures = true;
			CoreSettings.AllowSharingTrustsInRepositories = true;

			CoreSettings.EnforceAsymmetricSignatures.ShouldBeTrue();
			CoreSettings.AllowSharingTrustsInRepositories.ShouldBeTrue();

			CoreSettings.EnforceAsymmetricSignatures = false;
			CoreSettings.AllowSharingTrustsInRepositories = false;

			CoreSettings.EnforceAsymmetricSignatures.ShouldBeFalse();
			CoreSettings.AllowSharingTrustsInRepositories.ShouldBeFalse();
		}
	}
}
