using System;
using System.IO;
using System.Linq;
using Moq;
using NUnit.Framework;
using Shouldly;

namespace MSBuildGuard.Core.Scanning
{
    /// <summary>
    /// Contains unit tests for <see cref="MsBuildScanner"/>.
    /// </summary>
    [TestFixture]
    public sealed class MsBuildScannerTests
    {
        /// <summary>
        /// Verifies MBG001 detection when UsingTask contains inline code.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg001_WhenUsingTaskContainsCode()
        {
            var filePath = CreateProjectFile("<Project><UsingTask TaskName='T'><Task><Code Type='Class' Language='cs'><![CDATA[class T{}]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG001").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies MBG002 detection when UsingTask uses a dynamic code task factory.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg002_WhenUsingTaskHasCodeTaskFactory()
        {
            var filePath = CreateProjectFile("<Project><UsingTask TaskName='T' TaskFactory='RoslynCodeTaskFactory' AssemblyFile='x' /></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG002").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies MBG003 detection when InitialTargets is present.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg003_WhenInitialTargetsIsPresent()
        {
            var filePath = CreateProjectFile("<Project InitialTargets='PreBuild'><Target Name='PreBuild' /></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG003").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies MBG004 detection for early lifecycle hooks.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg004_WhenTargetHooksEarlyLifecycle()
        {
            var filePath = CreateProjectFile("<Project><Target Name='Hook' BeforeTargets='BeforeBuild' /></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG004").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies MBG005 detection for shell execution via Exec command.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg005_WhenExecRunsShell()
        {
            var filePath = CreateProjectFile("<Project><Target Name='Build'><Exec Command='powershell -NoProfile -Command Write-Host test' /></Target></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG005").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies import extraction from XML import elements.
        /// </summary>
        [Test]
        public void Scan_ShouldExtractImports_WhenImportElementsExist()
        {
            var filePath = CreateProjectFile("<Project><Import Project='shared.props' /></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);
            var scannedFile = report.FilesScanned.Single();

            scannedFile.Imports.Single().ShouldBe("shared.props");
        }

        /// <summary>
        /// Verifies imported files discovered from solution entries track fan-out metadata.
        /// </summary>
        [Test]
        public void Scan_ShouldResolveImportsAcrossSolution_AndTrackImportFanOut()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            Directory.CreateDirectory(rootPath);

            var solutionPath = Path.Combine(rootPath, "test.sln");
            var firstProjectPath = Path.Combine(rootPath, "App1.csproj");
            var secondProjectPath = Path.Combine(rootPath, "App2.csproj");
            var sharedTargetsPath = Path.Combine(rootPath, "shared.targets");

            File.WriteAllText(solutionPath, "Project(\"{GUID}\") = \"App1\", \"App1.csproj\", \"{GUID1}\"\nProject(\"{GUID}\") = \"App2\", \"App2.csproj\", \"{GUID2}\"");
            File.WriteAllText(firstProjectPath, "<Project><Import Project='shared.targets' /></Project>");
            File.WriteAllText(secondProjectPath, "<Project><Import Project='shared.targets' /></Project>");
            File.WriteAllText(sharedTargetsPath, "<Project><Target Name='Shared' /></Project>");

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(solutionPath);
            var sharedRecord = report.FilesScanned.Single(file => string.Equals(file.Path, sharedTargetsPath, StringComparison.OrdinalIgnoreCase));
            var importingProjects = report.FilesScanned.Where(file => file.FileKind == MsBuildFileKind.Project).ToList();

            sharedRecord.DiscoveredFrom.ShouldBe(FileDiscoverySource.Import);
            sharedRecord.ImportedByCount.ShouldBe(2);
            importingProjects.All(file => file.ResolvedImports.Single().IsImportedByMultipleProjects).ShouldBeTrue();
        }

        /// <summary>
        /// Verifies SLNX solution entries are expanded so contained projects are scanned.
        /// </summary>
        [Test]
        public void Scan_ShouldExpandSlnxProjectEntries_WhenTargetIsSlnxSolution()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            Directory.CreateDirectory(rootPath);

            var solutionPath = Path.Combine(rootPath, "test.slnx");
            var firstProjectPath = Path.Combine(rootPath, "App1.csproj");
            var secondProjectPath = Path.Combine(rootPath, "App2.csproj");
            var sharedTargetsPath = Path.Combine(rootPath, "shared.targets");

            File.WriteAllText(solutionPath, "<Solution><Project Path='App1.csproj' /><Project Path='App2.csproj' /></Solution>");
            File.WriteAllText(firstProjectPath, "<Project><Import Project='shared.targets' /></Project>");
            File.WriteAllText(secondProjectPath, "<Project><Import Project='shared.targets' /></Project>");
            File.WriteAllText(sharedTargetsPath, "<Project><Target Name='Shared' BeforeTargets='BeforeBuild' /></Project>");

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(solutionPath);
            var scannedProjectPaths = report.FilesScanned
                .Where(file => file.FileKind == MsBuildFileKind.Project)
                .Select(file => file.Path)
                .ToList();

            scannedProjectPaths.Any(path => string.Equals(path, firstProjectPath, StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
            scannedProjectPaths.Any(path => string.Equals(path, secondProjectPath, StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
            report.FilesScanned.Any(file => string.Equals(file.Path, sharedTargetsPath, StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
        }

        /// <summary>
        /// Verifies repeated identical inline code blocks are analyzed consistently during a single scan.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectRepeatedInlineCodeConsistently_WhenSameCodeAppearsMultipleTimes()
        {
            var inlineCode = "using System.Diagnostics; class T { void Run() { System.Diagnostics.Process.Start(\"cmd.exe\"); } }";
            var filePath = CreateProjectFile($"<Project><UsingTask TaskName='T1'><Task><Code Type='Class' Language='cs'><![CDATA[{inlineCode}]]></Code></Task></UsingTask><UsingTask TaskName='T2'><Task><Code Type='Class' Language='cs'><![CDATA[{inlineCode}]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Count(finding => finding.Id == "MBG006").ShouldBe(2);
        }

        /// <summary>
        /// Verifies repeated imports resolve consistently within one scan.
        /// </summary>
        [Test]
        public void Scan_ShouldResolveRepeatedImportsConsistently_WhenProjectImportsSameFileTwice()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            Directory.CreateDirectory(rootPath);

            var projectPath = Path.Combine(rootPath, "App.csproj");
            var sharedTargetsPath = Path.Combine(rootPath, "shared.targets");

            File.WriteAllText(projectPath, "<Project><Import Project='shared.targets' /><Import Project='shared.targets' /></Project>");
            File.WriteAllText(sharedTargetsPath, "<Project><Target Name='Shared' /></Project>");

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(projectPath);
            var projectRecord = report.FilesScanned.Single(file => string.Equals(file.Path, projectPath, StringComparison.OrdinalIgnoreCase));

            projectRecord.ResolvedImports.Count(importRecord => importRecord.IsResolved).ShouldBe(2);
            report.FilesScanned.Count(file => string.Equals(file.Path, sharedTargetsPath, StringComparison.OrdinalIgnoreCase)).ShouldBe(1);
        }

        /// <summary>
        /// Verifies environment-expanded imports preserve the resolution kind.
        /// </summary>
        [Test]
        public void Scan_ShouldMarkImportAsEnvironmentExpanded_WhenEnvironmentVariableResolvesPath()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            Directory.CreateDirectory(rootPath);

            var originalValue = Environment.GetEnvironmentVariable("MSBUILDGUARD_IMPORT_ROOT");
            var projectPath = Path.Combine(rootPath, "App.csproj");
            var sharedTargetsPath = Path.Combine(rootPath, "shared.targets");

            try
            {
                Environment.SetEnvironmentVariable("MSBUILDGUARD_IMPORT_ROOT", rootPath);
                File.WriteAllText(projectPath, "<Project><Import Project='%MSBUILDGUARD_IMPORT_ROOT%\\shared.targets' /></Project>");
                File.WriteAllText(sharedTargetsPath, "<Project><Target Name='Shared' /></Project>");

                var scanner = new MsBuildScanner();

                var report = scanner.Scan(projectPath);
                var projectRecord = report.FilesScanned.Single(file => string.Equals(file.Path, projectPath, StringComparison.OrdinalIgnoreCase));

                projectRecord.ResolvedImports.Single().ResolutionKind.ShouldBe(ImportResolutionKind.EnvironmentExpanded);
                projectRecord.ResolvedImports.Single().IsResolved.ShouldBeTrue();
            }
            finally
            {
                Environment.SetEnvironmentVariable("MSBUILDGUARD_IMPORT_ROOT", originalValue);
            }
        }

        /// <summary>
        /// Verifies SDK-style project declarations are captured as file metadata.
        /// </summary>
        [Test]
        public void Scan_ShouldCaptureSdkMetadata_WhenProjectUsesSdkAttribute()
        {
            var filePath = CreateProjectFile("<Project Sdk='Microsoft.NET.Sdk/9.0.100'><Target Name='Build' /></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);
            var scannedFile = report.FilesScanned.Single();

            scannedFile.SdkIdentifier.ShouldBe("Microsoft.NET.Sdk");
            scannedFile.SdkVersion.ShouldBe("9.0.100");
        }

        /// <summary>
        /// Verifies restored package build assets are scanned with package provenance metadata.
        /// </summary>
        [Test]
        public void Scan_ShouldCapturePackageAssetMetadata_WhenProjectAssetsReferenceNuGetTargets()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            var projectPath = Path.Combine(rootPath, "App.csproj");
            var objPath = Path.Combine(rootPath, "obj");
            var assetsFilePath = Path.Combine(objPath, "project.assets.json");
            var packagesRootPath = Path.Combine(rootPath, "packages");
            var packageTargetsPath = Path.Combine(packagesRootPath, "contoso.build", "1.2.3", "buildTransitive", "Contoso.Build.targets");

            Directory.CreateDirectory(rootPath);
            Directory.CreateDirectory(objPath);
            Directory.CreateDirectory(Path.GetDirectoryName(packageTargetsPath) ?? packagesRootPath);

            File.WriteAllText(projectPath, "<Project><Target Name='Build' /></Project>");
            File.WriteAllText(packageTargetsPath, "<Project><Target Name='Run' BeforeTargets='BeforeBuild' /></Project>");
            File.WriteAllText(assetsFilePath, $$"""
                {
                  "targets": {
                    ".NETCoreApp,Version=v10.0": {
                      "Contoso.Build/1.2.3": {
                        "type": "package",
                        "buildTransitive": {
                          "buildTransitive/Contoso.Build.targets": {}
                        }
                      }
                    }
                  },
                  "project": {
                    "restore": {
                      "projectPath": "{{projectPath.Replace("\\", "\\\\")}}",
                      "packagesPath": "{{packagesRootPath.Replace("\\", "\\\\")}}\\"
                    },
                    "frameworks": {
                      "net10.0": {
                        "dependencies": {
                          "Contoso.Build": {
                            "target": "Package",
                            "version": "[1.2.3, )"
                          }
                        }
                      }
                    }
                  }
                }
                """);

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(projectPath);
            var packageFile = report.FilesScanned.Single(file => string.Equals(file.Path, packageTargetsPath, StringComparison.OrdinalIgnoreCase));
            var packageFinding = report.Findings.Single(finding =>
              finding.Id == "MBG004" &&
              string.Equals(finding.FilePath, packageTargetsPath, StringComparison.OrdinalIgnoreCase));

            packageFile.DiscoveredFrom.ShouldBe(FileDiscoverySource.NuGetPackageAsset);
            packageFile.PackageId.ShouldBe("Contoso.Build");
            packageFile.PackageVersion.ShouldBe("1.2.3");
            packageFile.PackageAssetKind.ShouldBe(PackageAssetKind.BuildTransitive);
            packageFile.IsTransitivePackage.ShouldBeFalse();
            packageFile.IntroducedViaProject.ShouldBe(projectPath);
            packageFile.NuGetAssetPath.ShouldBe(packageTargetsPath);
            packageFinding.PackageId.ShouldBe("Contoso.Build");
            packageFinding.PackageVersion.ShouldBe("1.2.3");
            packageFinding.PackageAssetKind.ShouldBe(PackageAssetKind.BuildTransitive);
            packageFinding.IntroducedViaProject.ShouldBe(projectPath);
            packageFinding.NuGetAssetPath.ShouldBe(packageTargetsPath);
            packageFinding.IsTransitivePackage.ShouldBeFalse();
            report.Findings.Any(finding => finding.Id == "MBG004" && string.Equals(finding.FilePath, packageTargetsPath, StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
        }

        /// <summary>
        /// Verifies transitive package build assets are marked as transitive in scanned records and findings.
        /// </summary>
        [Test]
        public void Scan_ShouldMarkPackageAssetAsTransitive_WhenAssetsFileIntroducesTransitiveBuildAsset()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            var projectPath = Path.Combine(rootPath, "App.csproj");
            var objPath = Path.Combine(rootPath, "obj");
            var assetsFilePath = Path.Combine(objPath, "project.assets.json");
            var packagesRootPath = Path.Combine(rootPath, "packages");
            var directTargetsPath = Path.Combine(packagesRootPath, "contoso.direct", "2.0.0", "build", "Contoso.Direct.targets");
            var transitiveTargetsPath = Path.Combine(packagesRootPath, "fabrikam.transitive", "5.0.0", "buildTransitive", "Fabrikam.Transitive.targets");

            Directory.CreateDirectory(rootPath);
            Directory.CreateDirectory(objPath);
            Directory.CreateDirectory(Path.GetDirectoryName(directTargetsPath) ?? packagesRootPath);
            Directory.CreateDirectory(Path.GetDirectoryName(transitiveTargetsPath) ?? packagesRootPath);

            File.WriteAllText(projectPath, "<Project><Target Name='Build' /></Project>");
            File.WriteAllText(directTargetsPath, "<Project><Target Name='Direct' BeforeTargets='BeforeBuild' /></Project>");
            File.WriteAllText(transitiveTargetsPath, "<Project><Target Name='Transitive' BeforeTargets='BeforeBuild' /></Project>");
            File.WriteAllText(assetsFilePath, $$"""
                {
                  "targets": {
                    ".NETCoreApp,Version=v10.0": {
                      "Contoso.Direct/2.0.0": {
                        "type": "package",
                        "build": {
                          "build/Contoso.Direct.targets": {}
                        }
                      },
                      "Fabrikam.Transitive/5.0.0": {
                        "type": "package",
                        "buildTransitive": {
                          "buildTransitive/Fabrikam.Transitive.targets": {}
                        }
                      }
                    }
                  },
                  "project": {
                    "restore": {
                      "projectPath": "{{projectPath.Replace("\\", "\\\\")}}",
                      "packagesPath": "{{packagesRootPath.Replace("\\", "\\\\")}}\\"
                    },
                    "frameworks": {
                      "net10.0": {
                        "dependencies": {
                          "Contoso.Direct": {
                            "target": "Package",
                            "version": "[2.0.0, )"
                          }
                        }
                      }
                    }
                  }
                }
                """);

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(projectPath);
            var transitiveFile = report.FilesScanned.Single(file => string.Equals(file.Path, transitiveTargetsPath, StringComparison.OrdinalIgnoreCase));
            var transitiveFinding = report.Findings.Single(finding =>
              finding.Id == "MBG004" &&
              string.Equals(finding.FilePath, transitiveTargetsPath, StringComparison.OrdinalIgnoreCase));

            transitiveFile.PackageId.ShouldBe("Fabrikam.Transitive");
            transitiveFile.PackageAssetKind.ShouldBe(PackageAssetKind.BuildTransitive);
            transitiveFile.IsTransitivePackage.ShouldBeTrue();
            transitiveFinding.PackageId.ShouldBe("Fabrikam.Transitive");
            transitiveFinding.PackageAssetKind.ShouldBe(PackageAssetKind.BuildTransitive);
            transitiveFinding.IsTransitivePackage.ShouldBeTrue();
        }

        /// <summary>
        /// Verifies NuGet source mappings are attached to package-origin records and findings.
        /// </summary>
        [Test]
        public void Scan_ShouldCapturePackageSource_WhenNuGetConfigurationMapsPackage()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            var projectPath = Path.Combine(rootPath, "App.csproj");
            var nuGetConfigPath = Path.Combine(rootPath, "NuGet.config");
            var objPath = Path.Combine(rootPath, "obj");
            var assetsFilePath = Path.Combine(objPath, "project.assets.json");
            var packagesRootPath = Path.Combine(rootPath, "packages");
            var packageTargetsPath = Path.Combine(packagesRootPath, "contoso.build", "1.2.3", "build", "Contoso.Build.targets");

            Directory.CreateDirectory(rootPath);
            Directory.CreateDirectory(objPath);
            Directory.CreateDirectory(Path.GetDirectoryName(packageTargetsPath) ?? packagesRootPath);

            File.WriteAllText(projectPath, "<Project><Target Name='Build' /></Project>");
            File.WriteAllText(nuGetConfigPath, """
                <configuration>
                  <packageSources>
                    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
                    <add key="Contoso" value="https://packages.contoso.test/v3/index.json" />
                  </packageSources>
                  <packageSourceMapping>
                    <packageSource key="nuget.org">
                      <package pattern="*" />
                    </packageSource>
                    <packageSource key="Contoso">
                      <package pattern="Contoso.*" />
                    </packageSource>
                  </packageSourceMapping>
                </configuration>
                """);
            File.WriteAllText(packageTargetsPath, "<Project><Target Name='Run' BeforeTargets='BeforeBuild' /></Project>");
            File.WriteAllText(assetsFilePath, $$"""
                {
                  "targets": {
                    ".NETCoreApp,Version=v10.0": {
                      "Contoso.Build/1.2.3": {
                        "type": "package",
                        "build": {
                          "build/Contoso.Build.targets": {}
                        }
                      }
                    }
                  },
                  "project": {
                    "restore": {
                      "projectPath": "{{projectPath.Replace("\\", "\\\\")}}",
                      "packagesPath": "{{packagesRootPath.Replace("\\", "\\\\")}}\\"
                    },
                    "frameworks": {
                      "net10.0": {
                        "dependencies": {
                          "Contoso.Build": {
                            "target": "Package",
                            "version": "[1.2.3, )"
                          }
                        }
                      }
                    }
                  }
                }
                """);

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(projectPath);
            var packageFile = report.FilesScanned.Single(file => string.Equals(file.Path, packageTargetsPath, StringComparison.OrdinalIgnoreCase));
            var packageFinding = report.Findings.Single(finding =>
              finding.Id == "MBG004" &&
              string.Equals(finding.FilePath, packageTargetsPath, StringComparison.OrdinalIgnoreCase));

            packageFile.PackageSource.ShouldBe("https://packages.contoso.test/v3/index.json");
            packageFile.PackageSourceEvidenceKind.ShouldBe(PackageSourceEvidenceKind.ConfigMapping);
            packageFile.PackageSourceEvidencePath.ShouldBe(nuGetConfigPath);
            packageFile.IsPackageSourceInferred.ShouldBeTrue();
            packageFinding.PackageSource.ShouldBe("https://packages.contoso.test/v3/index.json");
            packageFinding.PackageSourceEvidenceKind.ShouldBe(PackageSourceEvidenceKind.ConfigMapping);
            packageFinding.PackageSourceEvidencePath.ShouldBe(nuGetConfigPath);
            packageFinding.IsPackageSourceInferred.ShouldBeTrue();
        }

        /// <summary>
        /// Verifies a single enabled package source is used as fallback when no source mapping exists.
        /// </summary>
        [Test]
        public void Scan_ShouldUseSingleEnabledPackageSource_WhenNoMappingMatches()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            var projectPath = Path.Combine(rootPath, "App.csproj");
            var nuGetConfigPath = Path.Combine(rootPath, "NuGet.config");
            var objPath = Path.Combine(rootPath, "obj");
            var assetsFilePath = Path.Combine(objPath, "project.assets.json");
            var packagesRootPath = Path.Combine(rootPath, "packages");
            var packageTargetsPath = Path.Combine(packagesRootPath, "fabrikam.tools", "4.5.6", "build", "Fabrikam.Tools.targets");

            Directory.CreateDirectory(rootPath);
            Directory.CreateDirectory(objPath);
            Directory.CreateDirectory(Path.GetDirectoryName(packageTargetsPath) ?? packagesRootPath);

            File.WriteAllText(projectPath, "<Project><Target Name='Build' /></Project>");
            File.WriteAllText(nuGetConfigPath, """
                <configuration>
                  <packageSources>
                    <add key="TrustedFeed" value="https://trusted.example/v3/index.json" />
                  </packageSources>
                </configuration>
                """);
            File.WriteAllText(packageTargetsPath, "<Project><Target Name='Run' BeforeTargets='BeforeBuild' /></Project>");
            File.WriteAllText(assetsFilePath, $$"""
                {
                  "targets": {
                    ".NETCoreApp,Version=v10.0": {
                      "Fabrikam.Tools/4.5.6": {
                        "type": "package",
                        "build": {
                          "build/Fabrikam.Tools.targets": {}
                        }
                      }
                    }
                  },
                  "project": {
                    "restore": {
                      "projectPath": "{{projectPath.Replace("\\", "\\\\")}}",
                      "packagesPath": "{{packagesRootPath.Replace("\\", "\\\\")}}\\"
                    },
                    "frameworks": {
                      "net10.0": {
                        "dependencies": {
                          "Fabrikam.Tools": {
                            "target": "Package",
                            "version": "[4.5.6, )"
                          }
                        }
                      }
                    }
                  }
                }
                """);

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(projectPath);
            var packageFile = report.FilesScanned.Single(file => string.Equals(file.Path, packageTargetsPath, StringComparison.OrdinalIgnoreCase));

            packageFile.PackageSource.ShouldBe("https://trusted.example/v3/index.json");
            packageFile.PackageSourceEvidenceKind.ShouldBe(PackageSourceEvidenceKind.SingleConfiguredSource);
            packageFile.PackageSourceEvidencePath.ShouldBe(nuGetConfigPath);
            packageFile.IsPackageSourceInferred.ShouldBeTrue();
        }

        /// <summary>
        /// Verifies restored package metadata source attribution overrides NuGet.config inference.
        /// </summary>
        [Test]
        public void Scan_ShouldPreferRestoredMetadata_WhenMetadataAndConfigAreAvailable()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            var projectPath = Path.Combine(rootPath, "App.csproj");
            var nuGetConfigPath = Path.Combine(rootPath, "NuGet.config");
            var objPath = Path.Combine(rootPath, "obj");
            var assetsFilePath = Path.Combine(objPath, "project.assets.json");
            var packagesRootPath = Path.Combine(rootPath, "packages");
            var packageVersionPath = Path.Combine(packagesRootPath, "contoso.build", "1.2.3");
            var packageTargetsPath = Path.Combine(packageVersionPath, "build", "Contoso.Build.targets");
            var metadataPath = Path.Combine(packageVersionPath, ".nupkg.metadata");

            Directory.CreateDirectory(rootPath);
            Directory.CreateDirectory(objPath);
            Directory.CreateDirectory(Path.GetDirectoryName(packageTargetsPath) ?? packagesRootPath);

            File.WriteAllText(projectPath, "<Project><Target Name='Build' /></Project>");
            File.WriteAllText(nuGetConfigPath, """
                <configuration>
                  <packageSources>
                    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
                    <add key="Contoso" value="https://packages.contoso.test/v3/index.json" />
                  </packageSources>
                  <packageSourceMapping>
                    <packageSource key="Contoso">
                      <package pattern="Contoso.*" />
                    </packageSource>
                  </packageSourceMapping>
                </configuration>
                """);
            File.WriteAllText(metadataPath, """
                {
                  "version": "2",
                  "contentHash": "metadata-hash",
                  "source": "https://restored.contoso.test/v3/index.json"
                }
                """);
            File.WriteAllText(packageTargetsPath, "<Project><Target Name='Run' BeforeTargets='BeforeBuild' /></Project>");
            File.WriteAllText(assetsFilePath, $$"""
                {
                  "targets": {
                    ".NETCoreApp,Version=v10.0": {
                      "Contoso.Build/1.2.3": {
                        "type": "package",
                        "build": {
                          "build/Contoso.Build.targets": {}
                        }
                      }
                    }
                  },
                  "project": {
                    "restore": {
                      "projectPath": "{{projectPath.Replace("\\", "\\\\")}}",
                      "packagesPath": "{{packagesRootPath.Replace("\\", "\\\\")}}\\"
                    },
                    "frameworks": {
                      "net10.0": {
                        "dependencies": {
                          "Contoso.Build": {
                            "target": "Package",
                            "version": "[1.2.3, )"
                          }
                        }
                      }
                    }
                  }
                }
                """);

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(projectPath);
            var packageFile = report.FilesScanned.Single(file => string.Equals(file.Path, packageTargetsPath, StringComparison.OrdinalIgnoreCase));
            var packageFinding = report.Findings.Single(finding =>
              finding.Id == "MBG004" &&
              string.Equals(finding.FilePath, packageTargetsPath, StringComparison.OrdinalIgnoreCase));

            packageFile.PackageSource.ShouldBe("https://restored.contoso.test/v3/index.json");
            packageFile.PackageSourceEvidenceKind.ShouldBe(PackageSourceEvidenceKind.RestoredMetadata);
            packageFile.PackageSourceEvidencePath.ShouldBe(metadataPath);
            packageFile.PackageContentHash.ShouldBe("metadata-hash");
            packageFile.IsPackageSourceInferred.ShouldBeFalse();
            packageFinding.PackageSource.ShouldBe("https://restored.contoso.test/v3/index.json");
            packageFinding.PackageSourceEvidenceKind.ShouldBe(PackageSourceEvidenceKind.RestoredMetadata);
            packageFinding.PackageSourceEvidencePath.ShouldBe(metadataPath);
            packageFinding.PackageContentHash.ShouldBe("metadata-hash");
            packageFinding.IsPackageSourceInferred.ShouldBeFalse();
        }

          /// <summary>
          /// Verifies malformed project.assets.json degrades analysis instead of terminating scan.
          /// </summary>
          [Test]
          public void Scan_ShouldMarkProjectAsPartialAndEmitMbg012_WhenProjectAssetsJsonIsMalformed()
          {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            var projectPath = Path.Combine(rootPath, "App.csproj");
            var objPath = Path.Combine(rootPath, "obj");
            var assetsFilePath = Path.Combine(objPath, "project.assets.json");

            Directory.CreateDirectory(rootPath);
            Directory.CreateDirectory(objPath);

            File.WriteAllText(projectPath, "<Project><Target Name='Build' /></Project>");
            File.WriteAllText(assetsFilePath, "{ \"targets\": { invalid-json }");

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(projectPath);
            var projectRecord = report.FilesScanned.Single(file => string.Equals(file.Path, projectPath, StringComparison.OrdinalIgnoreCase));

            projectRecord.AnalysisStatus.ShouldBe(AnalysisStatus.Partial);
            projectRecord.AnalysisSummary.ShouldContain("project.assets.json");
            report.Findings.Any(finding =>
              finding.Id == "MBG012" &&
              string.Equals(finding.FilePath, projectPath, StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
          }

        /// <summary>
        /// Verifies solution targets are marked as command-argument discoveries when scanned directly.
        /// </summary>
        [Test]
        public void Scan_ShouldMarkSolutionAsCommandArgument_WhenSolutionPathIsScannedDirectly()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}");
            Directory.CreateDirectory(rootPath);

            var solutionPath = Path.Combine(rootPath, "test.sln");
            var projectPath = Path.Combine(rootPath, "App.csproj");

            File.WriteAllText(solutionPath, "Project(\"{GUID}\") = \"App\", \"App.csproj\", \"{GUID1}\"");
            File.WriteAllText(projectPath, "<Project><Target Name='Build' /></Project>");

            var scanner = new MsBuildScanner();

            var report = scanner.Scan(solutionPath);
            var solutionRecord = report.FilesScanned.Single(file => string.Equals(file.Path, solutionPath, StringComparison.OrdinalIgnoreCase));

            solutionRecord.DiscoveredFrom.ShouldBe(FileDiscoverySource.CommandArgument);
            solutionRecord.FileKind.ShouldBe(MsBuildFileKind.Solution);
        }

        /// <summary>
        /// Verifies unresolved property-based imports produce partial analysis metadata.
        /// </summary>
        [Test]
        public void Scan_ShouldMarkAnalysisPartial_WhenImportCannotBeResolvedStatically()
        {
            var filePath = CreateProjectFile("<Project><Import Project='$(CustomTargets)' /></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);
            var scannedFile = report.FilesScanned.Single();

            report.AnalysisStatus.ShouldBe(AnalysisStatus.Partial);
            scannedFile.AnalysisStatus.ShouldBe(AnalysisStatus.Partial);
            scannedFile.ResolvedImports.Single().IsResolved.ShouldBeFalse();
            scannedFile.ResolvedImports.Single().ResolutionKind.ShouldBe(ImportResolutionKind.Unresolved);
            report.Findings.Any(finding => finding.Id == "MBG012").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies MBG006 detection for process creation indicators in inline code.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg006_WhenInlineCodeUsesProcessCreationApi()
        {
            var filePath = CreateProjectFile("<Project><UsingTask TaskName='T'><Task><Code Type='Class' Language='cs'><![CDATA[using System.Diagnostics; class T { void Run() { Process.Start(\"cmd.exe\"); } }]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG006").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies Roslyn-backed analysis detects process creation through fully-qualified invocations.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg006_WhenInlineCodeUsesFullyQualifiedProcessStart()
        {
            var filePath = CreateProjectFile("<Project><UsingTask TaskName='T'><Task><Code Type='Class' Language='cs'><![CDATA[class T { void Run() { System.Diagnostics.Process.Start(\"cmd.exe\"); } }]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG006").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies MBG007 detection for reflection or native interop indicators in inline code.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg007_WhenInlineCodeUsesReflectionOrInterop()
        {
            var filePath = CreateProjectFile("<Project><UsingTask TaskName='T'><Task><Code Type='Class' Language='cs'><![CDATA[using System.Reflection; class T { void Run() { Assembly.Load(\"X\"); } }]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG007").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies Roslyn-backed analysis detects interop usage via attributes.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg007_WhenInlineCodeUsesDllImportAttribute()
        {
            var filePath = CreateProjectFile("<Project><UsingTask TaskName='T'><Task><Code Type='Class' Language='cs'><![CDATA[using System.Runtime.InteropServices; class T { [DllImport(\"kernel32.dll\")] static extern void Beep(int f, int d); }]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG007").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies MBG008 detection for encoded payload indicators in inline code.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg008_WhenInlineCodeContainsLargeBase64()
        {
            var payload = new string('A', 220);
            var filePath = CreateProjectFile($"<Project><UsingTask TaskName='T'><Task><Code Type='Class' Language='cs'><![CDATA[class T {{ string P = \"{payload}\"; }}]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG008").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies Roslyn-backed analysis detects large inline byte-array allocations.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg008_WhenInlineCodeAllocatesLargeByteArray()
        {
            var filePath = CreateProjectFile("<Project><UsingTask TaskName='T'><Task><Code Type='Class' Language='cs'><![CDATA[class T { byte[] Payload = new byte[256]; }]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG008").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies MBG009 detection for risky import paths.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg009_WhenImportPathIsRisky()
        {
            var filePath = CreateProjectFile("<Project><Import Project='..\\..\\temp\\payload.targets' /></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG009").ShouldBeTrue();
        }

    /// <summary>
    /// Verifies MBG009 does not trigger for normalized in-repository imports that include safe traversal tokens.
    /// </summary>
    [Test]
    public void Scan_ShouldNotDetectMbg009_WhenImportResolvesToSafeLocalPath()
    {
      var rootPath = Path.Combine(AppContext.BaseDirectory, $"mbg-safe-import-{Guid.NewGuid():N}");
      var projectPath = Path.Combine(rootPath, "App.csproj");
      var importsPath = Path.Combine(rootPath, "imports");
      var safeTargetsPath = Path.Combine(importsPath, "safe.targets");

      Directory.CreateDirectory(rootPath);
      Directory.CreateDirectory(importsPath);

      File.WriteAllText(projectPath, "<Project><Import Project='imports\\..\\imports\\safe.targets' /></Project>");
      File.WriteAllText(safeTargetsPath, "<Project><Target Name='Safe' /></Project>");

      var scanner = new MsBuildScanner();

      var report = scanner.Scan(projectPath);

      report.Findings.Any(finding => finding.Id == "MBG009").ShouldBeFalse();
    }

    /// <summary>
    /// Verifies MBG009 uses conservative classification for unresolved property-based imports.
    /// </summary>
    [Test]
    public void Scan_ShouldDetectMbg009_WhenImportCannotBeResolved()
    {
      var filePath = CreateProjectFile("<Project><Import Project='$(CustomTargets)' /></Project>");
      var scanner = new MsBuildScanner();

      var report = scanner.Scan(filePath);

      report.Findings.Any(finding => finding.Id == "MBG009").ShouldBeTrue();
    }

    /// <summary>
    /// Verifies MBG010 is emitted by scanner for discovered .targets files without baseline comparison.
    /// </summary>
    [Test]
    public void Scan_ShouldEmitMbg010_WhenTargetsFileIsScannedWithoutBaseline()
    {
      var rootPath = Path.Combine(AppContext.BaseDirectory, $"mbg-targets-{Guid.NewGuid():N}");
      var projectPath = Path.Combine(rootPath, "App.csproj");
      var targetsPath = Path.Combine(rootPath, "custom.targets");

      Directory.CreateDirectory(rootPath);

      File.WriteAllText(projectPath, "<Project><Import Project='custom.targets' /></Project>");
      File.WriteAllText(targetsPath, "<Project><Target Name='Custom' /></Project>");

      var scanner = new MsBuildScanner();

      var report = scanner.Scan(projectPath);

      report.Findings.Any(finding =>
        finding.Id == "MBG010" &&
        string.Equals(finding.FilePath, targetsPath, StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
    }

        /// <summary>
        /// Verifies configurable file extensions participate in folder discovery.
        /// </summary>
        [Test]
        public void Scan_ShouldDiscoverConfiguredFileExtension_WhenCustomExtensionIsProvided()
        {
            var rootPath = Path.Combine(Path.GetTempPath(), $"msbuildguard-customext-{Guid.NewGuid():N}");
            var customProjectPath = Path.Combine(rootPath, "custom.projx");

            Directory.CreateDirectory(rootPath);
            File.WriteAllText(customProjectPath, "<Project><Target Name='Build' /></Project>");

            var scanner = new MsBuildScanner(
                fileSystem: null,
                activityLogger: null,
                msBuildExtensions: new[] { ".projx" },
                processCreationIndicators: null,
                reflectionInteropIndicators: null,
                additionalBlockedAssemblies: null);

            var report = scanner.Scan(rootPath);

            report.FilesScanned.Any(file => string.Equals(file.Path, customProjectPath, StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
        }

        /// <summary>
        /// Verifies configurable process indicators trigger MBG006 when Roslyn-only detection does not match.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg006_WhenCustomProcessIndicatorMatchesInlineCode()
        {
            var filePath = CreateProjectFile("<Project><UsingTask TaskName='T'><Task><Code Type='Class' Language='cs'><![CDATA[class T { void Run() { var cmd = \"launch_tool_xyz\"; } }]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner(
                fileSystem: null,
                activityLogger: null,
                msBuildExtensions: null,
                processCreationIndicators: new[] { "launch_tool_xyz" },
                reflectionInteropIndicators: null,
                additionalBlockedAssemblies: null);

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG006").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies configurable reflection indicators trigger MBG007 when Roslyn-only detection does not match.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg007_WhenCustomReflectionIndicatorMatchesInlineCode()
        {
            var filePath = CreateProjectFile("<Project><UsingTask TaskName='T'><Task><Code Type='Class' Language='cs'><![CDATA[class T { void Run() { var marker = \"magic_reflect_token\"; } }]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner(
                fileSystem: null,
                activityLogger: null,
                msBuildExtensions: null,
                processCreationIndicators: null,
                reflectionInteropIndicators: new[] { "magic_reflect_token" },
                additionalBlockedAssemblies: null);

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG007").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies configured blocked assemblies trigger MBG013 for matching reference includes.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg013_WhenBlockedAssemblyReferenceIsPresent()
        {
            var filePath = CreateProjectFile("<Project><ItemGroup><Reference Include='Forbidden.Assembly, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null' /></ItemGroup></Project>");
            var scanner = new MsBuildScanner(
                fileSystem: null,
                activityLogger: null,
                msBuildExtensions: null,
                processCreationIndicators: null,
                reflectionInteropIndicators: null,
                additionalBlockedAssemblies: new[] { "Forbidden.Assembly" });

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG013").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies report action mapping when high-risk findings are present.
        /// </summary>
        [Test]
        public void Scan_ShouldSetRequireApproval_WhenRiskScoreIsBetweenFiftyAndNinetyNine()
        {
            var filePath = CreateProjectFile("<Project><Target Name='Build'><Exec Command='cmd /c echo hi' /></Target></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.RiskScore.ShouldBeGreaterThanOrEqualTo(50);
            report.RiskScore.ShouldBeLessThan(100);
            report.RecommendedAction.ShouldBe(RecommendedAction.RequireApproval);
        }

        /// <summary>
        /// Verifies MBG012 detection when project content cannot be parsed.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg012_WhenProjectHasParseErrors()
        {
            var filePath = CreateProjectFile("<Project><Target Name='Broken'></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG012").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies MBG011 detection when Mark-of-the-Web metadata is present.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg011_WhenFileHasMarkOfTheWeb()
        {
            var filePath = CreateProjectFile("<Project><Target Name='Build' /></Project>");
            var motwPath = filePath + ":Zone.Identifier";
            var scanner = new MsBuildScanner();

            try
            {
                File.WriteAllText(motwPath, "[ZoneTransfer]\nZoneId=3");

                var report = scanner.Scan(filePath);

                report.Findings.Any(finding => finding.Id == "MBG011").ShouldBeTrue();
            }
            catch (NotSupportedException)
            {
                Assert.Ignore("Mark-of-the-Web alternate data streams are not supported on this filesystem.");
            }
            finally
            {
                try
                {
                    if (File.Exists(motwPath))
                    {
                        File.Delete(motwPath);
                    }
                }
                catch
                {
                }
            }
        }

        /// <summary>
        /// Verifies scanner behavior against a mocked file system implementation.
        /// </summary>
        [Test]
        public void Scan_ShouldUseInjectedFileSystem_WhenFileTargetIsProvided()
        {
            var filePath = Path.Combine(Path.GetTempPath(), "virtual.csproj");
            var xml = "<Project InitialTargets='Boot'><Target Name='Boot' /></Project>";
            var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);

            fileSystem.Setup(system => system.FileExists(filePath)).Returns(true);
            fileSystem.Setup(system => system.HasMarkOfTheWeb(filePath)).Returns(false);
            fileSystem.Setup(system => system.ReadAllText(filePath)).Returns(xml);

            var scanner = new MsBuildScanner(fileSystem.Object);

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG003").ShouldBeTrue();
            fileSystem.Verify(system => system.ReadAllText(filePath), Times.AtLeastOnce);
        }

        /// <summary>
        /// Verifies MBG011 detection can be driven by the injected file system abstraction.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectMbg011_WhenInjectedFileSystemReportsMarkOfTheWeb()
        {
            var filePath = Path.Combine(Path.GetTempPath(), "motw.csproj");
            var xml = "<Project><Target Name='Build' /></Project>";
            var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);

            fileSystem.Setup(system => system.FileExists(filePath)).Returns(true);
            fileSystem.Setup(system => system.HasMarkOfTheWeb(filePath)).Returns(true);
            fileSystem.Setup(system => system.ReadAllText(filePath)).Returns(xml);

            var scanner = new MsBuildScanner(fileSystem.Object);

            var report = scanner.Scan(filePath);

            report.Findings.Any(finding => finding.Id == "MBG011").ShouldBeTrue();
            fileSystem.Verify(system => system.HasMarkOfTheWeb(filePath), Times.AtLeastOnce);
        }

        /// <summary>
        /// Verifies sample PowerShell project content triggers MBG001 and MBG002.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectInlineTaskAndFactory_ForPowerShellSample()
        {
            var samplePath = CreateProjectFile("<Project><UsingTask TaskName='T' TaskFactory='RoslynCodeTaskFactory' AssemblyFile='x'><Task><Code Type='Class' Language='cs'><![CDATA[class T { static void Main(){ System.Diagnostics.Process.Start(\"powershell\"); } }]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(samplePath);

            report.Findings.Any(finding => finding.Id == "MBG001").ShouldBeTrue();
            report.Findings.Any(finding => finding.Id == "MBG002").ShouldBeTrue();
        }

        /// <summary>
        /// Verifies sample shellcode project content triggers MBG001 and MBG002.
        /// </summary>
        [Test]
        public void Scan_ShouldDetectInlineTaskAndFactory_ForShellcodeSample()
        {
            var samplePath = CreateProjectFile("<Project><UsingTask TaskName='T' TaskFactory='RoslynCodeTaskFactory' AssemblyFile='x'><Task><Code Type='Class' Language='cs'><![CDATA[class T { static void Main(){ byte[] shellcode = new byte[] { 0x90, 0x90 }; } }]]></Code></Task></UsingTask></Project>");
            var scanner = new MsBuildScanner();

            var report = scanner.Scan(samplePath);

            report.Findings.Any(finding => finding.Id == "MBG001").ShouldBeTrue();
            report.Findings.Any(finding => finding.Id == "MBG002").ShouldBeTrue();
        }

        /// <summary>
        /// Creates a temporary project file with provided content.
        /// </summary>
        /// <param name="content">The XML content to write.</param>
        /// <returns>The path of the created file.</returns>
        private static string CreateProjectFile(string content)
        {
            var filePath = Path.Combine(Path.GetTempPath(), $"msbuildguard-{Guid.NewGuid():N}.csproj");

            File.WriteAllText(filePath, content);

            return filePath;
        }

    }
}
