using System;
using System.IO;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Scanning
{
    /// <summary>
    /// Contains unit tests for <see cref="DefaultFileSystem"/>.
    /// </summary>
    [TestFixture]
    public sealed class DefaultFileSystemTests
    {
        /// <summary>
        /// Verifies existing file detection.
        /// </summary>
        [Test]
        public void FileExists_ShouldReturnTrue_WhenFileExists()
        {
            var filePath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}.tmp");
            var fileSystem = new DefaultFileSystem();

            File.WriteAllText(filePath, "content");

            var exists = fileSystem.FileExists(filePath);

            exists.ShouldBeTrue();
        }

        /// <summary>
        /// Verifies null path handling for file checks.
        /// </summary>
        [Test]
        public void FileExists_ShouldThrow_WhenPathIsNull()
        {
            var fileSystem = new DefaultFileSystem();

            Should.Throw<ArgumentNullException>(() => fileSystem.FileExists(null!));
        }

        /// <summary>
        /// Verifies Mark-of-the-Web checks return false when metadata is absent.
        /// </summary>
        [Test]
        public void HasMarkOfTheWeb_ShouldReturnFalse_WhenMetadataIsAbsent()
        {
            var filePath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}.tmp");
            var fileSystem = new DefaultFileSystem();

            File.WriteAllText(filePath, "content");

            var hasMarkOfTheWeb = fileSystem.HasMarkOfTheWeb(filePath);

            hasMarkOfTheWeb.ShouldBeFalse();
        }
    }
}
