using System;
using System.Collections.Generic;
using System.IO;

namespace MSBuildGuard.Core.Scanning
{
    /// <summary>
    /// Default file-system implementation backed by <see cref="System.IO"/>.
    /// </summary>
    public sealed class DefaultFileSystem : IFileSystem
    {
        /// <inheritdoc/>
        public bool FileExists(string path)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            return File.Exists(path);
        }

        /// <inheritdoc/>
        public bool DirectoryExists(string path)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            return Directory.Exists(path);
        }

        /// <inheritdoc/>
        public IEnumerable<string> EnumerateFiles(string path, string searchPattern)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            if (searchPattern == null)
            {
                throw new ArgumentNullException(nameof(searchPattern));
            }

            return Directory.EnumerateFiles(path, searchPattern, SearchOption.AllDirectories);
        }

        /// <inheritdoc/>
        public string ReadAllText(string path)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            return File.ReadAllText(path);
        }

        /// <inheritdoc/>
        public bool HasMarkOfTheWeb(string path)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            try
            {
                var motwPath = string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0}:Zone.Identifier", path);

                return File.Exists(motwPath);
            }
            catch
            {
                return false;
            }
        }
    }
}
