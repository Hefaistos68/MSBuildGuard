using MSBuildGuard.Core.Extensions;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Tests.Extensions
{
	/// <summary>
	/// Contains unit tests for <see cref="StringExtensions"/>.
	/// </summary>
	[TestFixture]
	public sealed class StringExtensionsTests
	{
		/// <summary>
		/// Verifies null input is returned unchanged.
		/// </summary>
		[Test]
		public void TrimMiddlePath_ShouldReturnNull_WhenInputIsNull()
		{
			string? value = null;

			var result = value.TrimMiddlePath(10);

			result.ShouldBeNull();
		}

		/// <summary>
		/// Verifies values that already fit in the limit are returned unchanged.
		/// </summary>
		[Test]
		public void TrimMiddlePath_ShouldReturnOriginal_WhenValueFitsMaxLength()
		{
			var value = "C:\\src\\a.csproj";

			var result = value.TrimMiddlePath(value.Length);

			result.ShouldBe(value);
		}

		/// <summary>
		/// Verifies single-segment values use fallback middle trimming.
		/// </summary>
		[Test]
		public void TrimMiddlePath_ShouldUseFallback_WhenValueHasNoPathSeparators()
		{
			var value = "abcdefghijklmnopqrstuvwxyz";

			var result = value.TrimMiddlePath(10);

			result.ShouldBe("abc...wxyz");
		}

		/// <summary>
		/// Verifies path-like values keep first and last segment with ellipsis marker.
		/// </summary>
		[Test]
		public void TrimMiddlePath_ShouldPreserveFirstAndLastSegments_WhenPathIsTrimmed()
		{
			var value = "C:\\very\\long\\path\\to\\my\\file.txt";

			var result = value.TrimMiddlePath(20);

			result.Length.ShouldBeLessThanOrEqualTo(20);
			result.StartsWith("C:\\").ShouldBeTrue();
			result.EndsWith("\\file.txt").ShouldBeTrue();
			result.Contains("...").ShouldBeTrue();
		}

		/// <summary>
		/// Verifies trimming falls back to first/last compression when first+last exceed max length.
		/// </summary>
		[Test]
		public void TrimMiddlePath_ShouldFallbackToFirstAndLastCompression_WhenFirstAndLastExceedLimit()
		{
			var value = "verylongfirstsegment\\folder\\verylonglastsegment";

			var result = value.TrimMiddlePath(12);

			result.Length.ShouldBeLessThanOrEqualTo(12);
			result.Contains("...").ShouldBeTrue();
		}

		/// <summary>
		/// Verifies very small max lengths return a simple left substring.
		/// </summary>
		[Test]
		public void TrimMiddlePath_ShouldReturnLeftSubstring_WhenMaxLengthIsVerySmall()
		{
			var value = "C:\\folder\\file.txt";

			var result = value.TrimMiddlePath(3);

			result.ShouldBe("C:\\");
		}
	}
}
