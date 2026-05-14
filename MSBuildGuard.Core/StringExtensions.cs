using System;

namespace MSBuildGuard.Core.Extensions
{
	/// <summary>
	/// Provides string helper extension methods for model formatting.
	/// </summary>
	public static class StringExtensions
	{
		/// <summary>
		/// Trims a path-like string in the middle while preserving both start and end segments.
		/// </summary>
		/// <param name="value">The input string.</param>
		/// <param name="maxLength">The maximum output length.</param>
		/// <returns>The original string when no trimming is needed; otherwise a middle-trimmed value.</returns>
		public static string TrimMiddlePath(this string value, int maxLength)
		{
			if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
			{
				return value;
			}

			var segments = value.Split(new[] { '\\' }, StringSplitOptions.None);

			if (segments.Length < 2)
			{
				return TrimMiddleFallback(value, maxLength);
			}

			var first = segments[0];
			var last = segments[segments.Length - 1];
			var firstAndLast = first + "\\" + last;

			if (firstAndLast.Length > maxLength)
			{
				return TrimMiddleFallback(firstAndLast, maxLength);
			}

			var working = new System.Collections.Generic.List<string>(segments);
			var middleIndex = working.Count / 2;

			working[middleIndex] = "...";

			while (working.Count > 2 && string.Join("\\", working).Length > maxLength)
			{
				var markerIndex = working.IndexOf("...");
				var leftIndex = markerIndex - 1;

				if (leftIndex >= 0)
				{
					working.RemoveAt(leftIndex);
				}

				if (string.Join("\\", working).Length <= maxLength)
				{
					break;
				}

				markerIndex = working.IndexOf("...");
				var rightIndex = markerIndex + 1;

				if (rightIndex < working.Count)
				{
					working.RemoveAt(rightIndex);
				}
				else
				{
					break;
				}
			}

			var candidate = string.Join("\\", working);

			if (candidate.Length <= maxLength)
			{
				return candidate;
			}

			return TrimMiddleFallback(firstAndLast, maxLength);
		}

		/// <summary>
		/// Trims a string in the middle using the original fixed middle marker strategy.
		/// </summary>
		/// <param name="value">The input string.</param>
		/// <param name="maxLength">The maximum output length.</param>
		/// <returns>A trimmed string that fits in the given maximum length.</returns>
		private static string TrimMiddleFallback(string value, int maxLength)
		{
			const string middle = "...";
			var available = maxLength - middle.Length;

			if (available <= 4)
			{
				return value.Substring(0, maxLength);
			}

			var headLength = available / 2;
			var tailLength = available - headLength;
			var head = value.Substring(0, headLength);
			var tail = value.Substring(value.Length - tailLength, tailLength);

			return head + middle + tail;
		}
	}
}
