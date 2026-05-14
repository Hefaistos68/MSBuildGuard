using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace MSBuildGuard.VisualStudio.Services
{
	/// <summary>
	/// Provides path redaction helpers for UI and log messages.
	/// </summary>
	internal static class PathRedactionService
	{
		private static readonly string[] CandidatePathRoots = new[]
		{
			Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
			Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
			Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
			Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
			Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
			Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
		};

		private static readonly Dictionary<string, string> RootTokenMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
		{
			{ Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "%USERPROFILE%" },
			{ Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "%LOCALAPPDATA%" },
			{ Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "%APPDATA%" },
			{ Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "%PROGRAMDATA%" },
			{ Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "%USERPROFILE%\\Documents" },
			{ Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "%USERPROFILE%\\Desktop" }
		};

		/// <summary>
		/// Redacts a single file-system path for display.
		/// </summary>
		/// <param name="path">The original absolute or relative path.</param>
		/// <returns>The redacted display path.</returns>
		public static string RedactPath(string path)
		{
			if (string.IsNullOrWhiteSpace(path))
			{
				return string.Empty;
			}

			var normalized = path.Replace('/', Path.DirectorySeparatorChar).Trim();

			foreach (var root in RootTokenMap.Keys.Where(key => !string.IsNullOrWhiteSpace(key)).OrderByDescending(key => key.Length))
			{
				if (!normalized.StartsWith(root, StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				var token = RootTokenMap[root];
				var suffix = normalized.Substring(root.Length);

				if (suffix.StartsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
				{
					return token + suffix;
				}

				if (string.IsNullOrEmpty(suffix))
				{
					return token;
				}

				return token + Path.DirectorySeparatorChar + suffix;
			}

			return normalized;
		}

		/// <summary>
		/// Redacts known absolute paths occurring in a text message.
		/// </summary>
		/// <param name="message">The message to sanitize.</param>
		/// <returns>The sanitized message.</returns>
		public static string RedactMessage(string message)
		{
			if (string.IsNullOrWhiteSpace(message))
			{
				return string.Empty;
			}

			var redacted = message;

			foreach (var root in CandidatePathRoots.Where(root => !string.IsNullOrWhiteSpace(root)).OrderByDescending(root => root.Length))
			{
				if (redacted.IndexOf(root, StringComparison.OrdinalIgnoreCase) < 0)
				{
					continue;
				}

				redacted = ReplaceOrdinalIgnoreCase(redacted, root, RootTokenMap[root]);
			}

			return redacted;
		}

		private static string ReplaceOrdinalIgnoreCase(string source, string oldValue, string newValue)
		{
			if (string.IsNullOrEmpty(source) || string.IsNullOrEmpty(oldValue))
			{
				return source;
			}

			var startIndex = 0;
			var index = source.IndexOf(oldValue, StringComparison.OrdinalIgnoreCase);

			if (index < 0)
			{
				return source;
			}

			var builder = new System.Text.StringBuilder();

			while (index >= 0)
			{
				builder.Append(source, startIndex, index - startIndex);
				builder.Append(newValue);
				startIndex = index + oldValue.Length;
				index = source.IndexOf(oldValue, startIndex, StringComparison.OrdinalIgnoreCase);
			}

			builder.Append(source, startIndex, source.Length - startIndex);

			return builder.ToString();
		}
	}
}
