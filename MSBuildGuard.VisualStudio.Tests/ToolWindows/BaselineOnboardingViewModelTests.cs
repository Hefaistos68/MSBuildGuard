using System.Collections.Generic;
using MSBuildGuard.Core.Baseline;
using MSBuildGuard.VisualStudio.ToolWindows;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.VisualStudio.ToolWindows.Tests
{
	/// <summary>
	/// Tests for <see cref="BaselineOnboardingViewModel"/>.
	/// </summary>
	[TestFixture]
	public sealed class BaselineOnboardingViewModelTests
	{
		/// <summary>
		/// Verifies that properties are initialized to their default values.
		/// </summary>
		[Test]
		public void Constructor_ShouldInitializePropertiesToDefaults()
		{
			var suggestions = new List<TrustSuggestion>();
			var viewModel   = new BaselineOnboardingViewModel(suggestions);

			viewModel.Suggestions.ShouldBeEmpty();
			viewModel.CreateBaselineForRemaining.ShouldBeTrue();
			viewModel.DoNotScanAgain.ShouldBeFalse();
			viewModel.DontShowAgain.ShouldBeFalse();
			viewModel.SelectedTrustScope.ShouldBe("Solution");
			viewModel.AvailableTrustScopes.ShouldContain("User");
			viewModel.AvailableTrustScopes.ShouldContain("Solution");
			viewModel.AvailableTrustScopes.ShouldContain("Project");
		}

		/// <summary>
		/// Verifies that setting SelectedTrustScope updates the value and triggers PropertyChanged.
		/// </summary>
		[Test]
		public void SelectedTrustScope_ShouldChangeValueAndRaiseNotification()
		{
			var suggestions = new List<TrustSuggestion>();
			var viewModel   = new BaselineOnboardingViewModel(suggestions);
			var raised      = false;

			viewModel.PropertyChanged += (sender, args) =>
			{
				if (args.PropertyName == nameof(BaselineOnboardingViewModel.SelectedTrustScope))
				{
					raised = true;
				}
			};

			viewModel.SelectedTrustScope = "User";

			viewModel.SelectedTrustScope.ShouldBe("User");
			raised.ShouldBeTrue();
		}
	}
}
