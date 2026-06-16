using MSBuildGuard.VisualStudio.Options;
using MSBuildGuard.VisualStudio.ToolWindows;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.VisualStudio.ToolWindows.Tests
{
	/// <summary>
	/// Tests for <see cref="KeyManagementOnboardingViewModel"/>.
	/// </summary>
	[TestFixture]
	public sealed class KeyManagementOnboardingViewModelTests
	{
		/// <summary>
		/// Verifies that the view model initializes with SelectedMode set to Unconfigured.
		/// </summary>
		[Test]
		public void Constructor_ShouldInitializeWithUnconfiguredMode()
		{
			var viewModel = new KeyManagementOnboardingViewModel();

			viewModel.SelectedMode.ShouldBe(KeyManagementModeKind.Unconfigured);
		}

		/// <summary>
		/// Verifies that SelectedMode can be changed and retrieved successfully.
		/// </summary>
		[Test]
		public void SelectedMode_ShouldStoreAndRetrieveValue()
		{
			var viewModel = new KeyManagementOnboardingViewModel();

			viewModel.SelectedMode = KeyManagementModeKind.DPAPI;

			viewModel.SelectedMode.ShouldBe(KeyManagementModeKind.DPAPI);
		}
	}
}
