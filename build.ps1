# ShadowOps Build Script for Windows PowerShell
# Advanced Cybersecurity Framework v2.0.0
# Author: ShadowOps Team

param(
    [string]$BuildType = "Release",
    [string]$Architecture = "x64",
    [switch]$Clean,
    [switch]$Tests,
    [switch]$Documentation,
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to check Windows version
function Get-WindowsVersion {
    try {
        $version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
        return $version
    } catch {
        return "Unknown"
    }
}

# Function to check Visual Studio installation
function Test-VisualStudio {
    $vsPaths = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    )
    
    foreach ($path in $vsPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    return $null
}

# Function to check CMake installation
function Test-CMake {
    try {
        $cmakeVersion = cmake --version 2>$null | Select-String "cmake version"
        if ($cmakeVersion) {
            return $cmakeVersion.ToString().Split(" ")[2]
        }
    } catch {
        return $null
    }
    return $null
}

# Function to check Git installation
function Test-Git {
    try {
        $gitVersion = git --version 2>$null | Select-String "git version"
        if ($gitVersion) {
            return $gitVersion.ToString().Split(" ")[2]
        }
    } catch {
        return $null
    }
    return $null
}

# Function to create build directory
function New-BuildDirectory {
    param([string]$Path)
    
    if (Test-Path $Path) {
        if ($Clean) {
            Write-ColorOutput "Cleaning existing build directory..." "Yellow"
            Remove-Item $Path -Recurse -Force
        } else {
            Write-ColorOutput "Build directory already exists, using existing..." "Yellow"
        }
    }
    
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
        Write-ColorOutput "Created build directory: $Path" "Green"
    }
}

# Function to configure CMake
function Invoke-CMakeConfigure {
    param(
        [string]$SourceDir,
        [string]$BuildDir,
        [string]$Generator,
        [string]$Arch
    )
    
    $cmakeArgs = @(
        $SourceDir,
        "-G", $Generator,
        "-A", $Arch,
        "-DCMAKE_BUILD_TYPE=$BuildType"
    )
    
    if ($Tests) {
        $cmakeArgs += "-DBUILD_TESTS=ON"
    }
    
    if ($Documentation) {
        $cmakeArgs += "-DENABLE_DOCS=ON"
    }
    
    Write-ColorOutput "Configuring with CMake..." "Cyan"
    Write-ColorOutput "Generator: $Generator" "Gray"
    Write-ColorOutput "Architecture: $Arch" "Gray"
    Write-ColorOutput "Build Type: $BuildType" "Gray"
    
    $process = Start-Process -FilePath "cmake" -ArgumentList $cmakeArgs -WorkingDirectory $BuildDir -PassThru -NoNewWindow -Wait
    
    if ($process.ExitCode -ne 0) {
        throw "CMake configuration failed with exit code: $($process.ExitCode)"
    }
    
    Write-ColorOutput "CMake configuration completed successfully" "Green"
}

# Function to build project
function Invoke-CMakeBuild {
    param([string]$BuildDir)
    
    Write-ColorOutput "Building project..." "Cyan"
    Write-ColorOutput "This may take several minutes depending on your system..." "Gray"
    
    $buildArgs = @(
        "--build", ".",
        "--config", $BuildType,
        "--parallel"
    )
    
    $process = Start-Process -FilePath "cmake" -ArgumentList $buildArgs -WorkingDirectory $BuildDir -PassThru -NoNewWindow -Wait
    
    if ($process.ExitCode -ne 0) {
        throw "Build failed with exit code: $($process.ExitCode)"
    }
    
    Write-ColorOutput "Build completed successfully!" "Green"
}

# Function to validate build output
function Test-BuildOutput {
    param([string]$BuildDir)
    
    $exePath = Join-Path $BuildDir "$BuildType\shadowops.exe"
    
    if (-not (Test-Path $exePath)) {
        throw "Executable not found at expected location: $exePath"
    }
    
    $fileInfo = Get-Item $exePath
    $fileSize = [math]::Round($fileInfo.Length / 1MB, 2)
    
    Write-ColorOutput "Executable created successfully:" "Green"
    Write-ColorOutput "  Path: $exePath" "Gray"
    Write-ColorOutput "  Size: $fileSize MB" "Gray"
    Write-ColorOutput "  Created: $($fileInfo.CreationTime)" "Gray"
    
    return $exePath
}

# Function to setup configuration
function Setup-Configuration {
    param([string]$BuildDir)
    
    $configSource = Join-Path (Split-Path $BuildDir -Parent) "shadowops.conf"
    $configDest = Join-Path $BuildDir "$BuildType\shadowops.conf"
    
    if (Test-Path $configSource) {
        Copy-Item $configSource $configDest -Force
        Write-ColorOutput "Configuration file copied to build directory" "Green"
    } else {
        Write-ColorOutput "Creating default configuration file..." "Yellow"
        $defaultConfig = @(
            "# ShadowOps Configuration File",
            "target_process=C:\Windows\explorer.exe",
            "enable_logging=true",
            "enable_evasion=true",
            "enable_anti_debug=true",
            "enable_anti_vm=true"
        )
        $defaultConfig | Out-File -FilePath $configDest -Encoding UTF8
        Write-ColorOutput "Default configuration file created" "Green"
    }
}

# Function to create sample payload
function New-SamplePayload {
    param([string]$BuildDir)
    
    $payloadPath = Join-Path $BuildDir "$BuildType\payload.bin"
    
    if (-not (Test-Path $payloadPath)) {
        Write-ColorOutput "Creating sample payload file..." "Yellow"
        $sampleContent = @(
            "This is a sample payload file for testing purposes.",
            "Replace this with your actual payload before deployment.",
            "",
            "Generated on: $(Get-Date)",
            "ShadowOps v2.0.0 - https://github.com/Kumarabhijeet1608/ShadowOps"
        )
        $sampleContent | Out-File -FilePath $payloadPath -Encoding UTF8
        Write-ColorOutput "Sample payload file created" "Green"
    }
}

# Function to create deployment package
function New-DeploymentPackage {
    param([string]$BuildDir)
    
    $deployDir = Join-Path $BuildDir "deploy"
    $releaseDir = Join-Path $BuildDir $BuildType
    
    if (-not (Test-Path $deployDir)) {
        New-Item -ItemType Directory -Path $deployDir | Out-Null
    }
    
    # Copy files
    $filesToCopy = @(
        @{Source = "shadowops.exe"; Dest = "shadowops.exe"},
        @{Source = "shadowops.conf"; Dest = "shadowops.conf"},
        @{Source = "payload.bin"; Dest = "payload.bin"}
    )
    
    foreach ($file in $filesToCopy) {
        $sourcePath = Join-Path $releaseDir $file.Source
        $destPath = Join-Path $deployDir $file.Dest
        
        if (Test-Path $sourcePath) {
            Copy-Item $sourcePath $destPath -Force
        }
    }
    
    # Copy documentation
    $docFiles = @("README.md", "LICENSE")
    foreach ($docFile in $docFiles) {
        $sourcePath = Join-Path (Split-Path $BuildDir -Parent) $docFile
        $destPath = Join-Path $deployDir $docFile
        
        if (Test-Path $sourcePath) {
            Copy-Item $sourcePath $destPath -Force
        }
    }
    
    # Create run script
    $runScript = @(
        "@echo off",
        "echo Starting ShadowOps...",
        "shadowops.exe",
        "pause"
    )
            $runScript | Out-File -FilePath (Join-Path $deployDir "run_shadowops.bat") -Encoding ASCII
    
    Write-ColorOutput "Deployment package created in: $deployDir" "Green"
}

# Function to display build summary
function Show-BuildSummary {
    param(
        [string]$BuildDir,
        [string]$ExePath
    )
    
    Write-ColorOutput "" "White"
    Write-ColorOutput "===================================================" "Cyan"
    Write-ColorOutput "⚔️  BUILD SUMMARY ⚔️" "Cyan"
    Write-ColorOutput "===================================================" "Cyan"
    Write-ColorOutput "[SUCCESS] ShadowOps v2.0.0 built successfully!" "Green"
    Write-ColorOutput "" "White"
    
    Write-ColorOutput "Build Details:" "Yellow"
    Write-ColorOutput "- Build Type: $BuildType" "Gray"
    Write-ColorOutput "- Architecture: $Architecture" "Gray"
    Write-ColorOutput "- Output: $ExePath" "Gray"
    Write-ColorOutput "- Configuration: $(Join-Path $BuildDir "$BuildType\shadowops.conf")" "Gray"
    Write-ColorOutput "- Deployment: $(Join-Path $BuildDir "deploy\")" "Gray"
    
    Write-ColorOutput "" "White"
    Write-ColorOutput "Next Steps:" "Yellow"
    Write-ColorOutput "1. Review and modify shadowops.conf as needed" "Gray"
    Write-ColorOutput "2. Replace payload.bin with your actual payload" "Gray"
    Write-ColorOutput "3. Test in a controlled environment" "Gray"
    Write-ColorOutput "4. Deploy to target systems" "Gray"
    
    Write-ColorOutput "" "White"
    Write-ColorOutput "⚠️  IMPORTANT: This tool is for educational and authorized testing only!" "Red"
    Write-ColorOutput "⚠️  Ensure compliance with all applicable laws and regulations." "Red"
    
    Write-ColorOutput "" "White"
    Write-ColorOutput "===================================================" "Cyan"
}

# Main execution
try {
    # Display header
    Write-ColorOutput "" "White"
    Write-ColorOutput "⚔️ ShadowOps Advanced Cybersecurity Framework ⚔️" "Cyan"
    Write-ColorOutput "==================================================" "Cyan"
    Write-ColorOutput "Version: 2.0.0" "White"
    Write-ColorOutput "Build Date: $(Get-Date)" "White"
    Write-ColorOutput "" "White"
    
    # Check environment
    Write-ColorOutput "Checking environment..." "Yellow"
    
    # Check administrator privileges
    if (Test-Administrator) {
        Write-ColorOutput "[INFO] Running with administrator privileges" "Green"
    } else {
        Write-ColorOutput "[WARNING] Not running as administrator - some features may be limited" "Yellow"
    }
    
    # Check Windows version
    $winVersion = Get-WindowsVersion
    Write-ColorOutput "[INFO] Windows Version: $winVersion" "White"
    
    # Check Visual Studio
    $vsPath = Test-VisualStudio
    if ($vsPath) {
        Write-ColorOutput "[INFO] Visual Studio found: $vsPath" "Green"
    } else {
        throw "Visual Studio not found. Please install Visual Studio 2019 or 2022."
    }
    
    # Check CMake
    $cmakeVersion = Test-CMake
    if ($cmakeVersion) {
        Write-ColorOutput "[INFO] CMake found: $cmakeVersion" "Green"
    } else {
        throw "CMake not found. Please install CMake from https://cmake.org/download/"
    }
    
    # Check Git
    $gitVersion = Test-Git
    if ($gitVersion) {
        Write-ColorOutput "[INFO] Git found: $gitVersion" "Green"
    } else {
        Write-ColorOutput "[WARNING] Git not found - version information may be incomplete" "Yellow"
    }
    
    # Create build directory
    $buildDir = Join-Path (Get-Location) "build"
    New-BuildDirectory -Path $buildDir
    
    # Configure with CMake
    $generator = "Visual Studio 16 2019"
    Invoke-CMakeConfigure -SourceDir (Split-Path $buildDir -Parent) -BuildDir $buildDir -Generator $generator -Arch $Architecture
    
    # Build project
    Invoke-CMakeBuild -BuildDir $buildDir
    
    # Validate build output
    $exePath = Test-BuildOutput -BuildDir $buildDir
    
    # Setup configuration
    Setup-Configuration -BuildDir $buildDir
    
    # Create sample payload
    New-SamplePayload -BuildDir $buildDir
    
    # Create deployment package
    New-DeploymentPackage -BuildDir $buildDir
    
    # Display summary
    Show-BuildSummary -BuildDir $buildDir -ExePath $exePath
    
    Write-ColorOutput "[INFO] Build script completed successfully!" "Green"
    
} catch {
    Write-ColorOutput "[ERROR] Build failed: $($_.Exception.Message)" "Red"
    if ($Verbose) {
        Write-ColorOutput "[ERROR] Stack trace: $($_.ScriptStackTrace)" "Red"
    }
    exit 1
}
