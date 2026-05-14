using System.Collections.Generic;

namespace MSBuildGuard.Core.Scanning
{
    /// <summary>
    /// Provides file-system access abstractions for scanner operations.
    /// </summary>
    public interface IFileSystem
    {
        /// <summary>
        /// Determines whether a file exists.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns><see langword="true"/> when the file exists; otherwise, <see langword="false"/>.</returns>
        bool FileExists(string path);

        /// <summary>
        /// Determines whether a directory exists.
        /// </summary>
        /// <param name="path">The directory path.</param>
        /// <returns><see langword="true"/> when the directory exists; otherwise, <see langword="false"/>.</returns>
        bool DirectoryExists(string path);

        /// <summary>
        /// Enumerates files from a directory.
        /// </summary>
        /// <param name="path">The directory path.</param>
        /// <param name="searchPattern">The search pattern.</param>
        /// <returns>A sequence of file paths.</returns>
        IEnumerable<string> EnumerateFiles(string path, string searchPattern);

        /// <summary>
        /// Reads all file text.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns>The file content.</returns>
        string ReadAllText(string path);

        /// <summary>
        /// Determines whether a file has Mark-of-the-Web metadata.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns><see langword="true"/> when Mark-of-the-Web metadata is present; otherwise, <see langword="false"/>.</returns>
        bool HasMarkOfTheWeb(string path);
    }
}
