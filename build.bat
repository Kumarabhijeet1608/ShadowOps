@echo off
REM ShadowOps Build Script for Windows
REM Advanced Cybersecurity Framework v2.0.0
REM Author: ShadowOps Team

setlocal enabledelayedexpansion

echo.
echo ⚔️ ShadowOps Advanced Cybersecurity Framework ⚔️
echo ===================================================
echo Version: 2.0.0
echo Build Date: %date% %time%
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Running with administrator privileges
) else (
    echo [WARNING] Not running as administrator - some features may be limited
)

REM Check Windows version
for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j
echo [INFO] Windows Version: %VERSION%

REM Check if Visual Studio is available
echo [INFO] Checking for Visual Studio...
where cl >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Visual Studio compiler found
    set COMPILER=msvc
) else (
    echo [ERROR] Visual Studio compiler not found in PATH
    echo [INFO] Please run this script from a Visual Studio Developer Command Prompt
    echo [INFO] Or add Visual Studio to your system PATH
    pause
    exit /b 1
)

REM Check if CMake is available
echo [INFO] Checking for CMake...
where cmake >nul 2>&1
if %errorLevel% == 0 (
    for /f "tokens=3" %%i in ('cmake --version 2^>^&1 ^| findstr "cmake version"') do set CMAKE_VERSION=%%i
    echo [INFO] CMake found: %CMAKE_VERSION%
) else (
    echo [ERROR] CMake not found
    echo [INFO] Please install CMake from https://cmake.org/download/
    pause
    exit /b 1
)

REM Check if Git is available
echo [INFO] Checking for Git...
where git >nul 2>&1
if %errorLevel% == 0 (
    for /f "tokens=3" %%i in ('git --version 2^>^&1 ^| findstr "git version"') do set GIT_VERSION=%%i
    echo [INFO] Git found: %GIT_VERSION%
) else (
    echo [WARNING] Git not found - version information may be incomplete
)

REM Create build directory
if not exist "build" (
    echo [INFO] Creating build directory...
    mkdir build
) else (
    echo [INFO] Build directory already exists
)

REM Navigate to build directory
cd build

REM Configure with CMake
echo.
echo [INFO] Configuring project with CMake...
echo [INFO] Build Type: Release
echo [INFO] Architecture: x64
echo.

cmake .. -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
if %errorLevel% neq 0 (
    echo [ERROR] CMake configuration failed
    echo [INFO] Trying alternative generator...
    cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
    if %errorLevel% neq 0 (
        echo [ERROR] CMake configuration failed with all generators
        pause
        exit /b 1
    )
)

echo.
echo [INFO] CMake configuration completed successfully

REM Build the project
echo.
echo [INFO] Building project...
echo [INFO] This may take several minutes depending on your system...
echo.

cmake --build . --config Release --parallel
if %errorLevel% neq 0 (
    echo [ERROR] Build failed
    echo [INFO] Check the build output above for errors
    pause
    exit /b 1
)

echo.
echo [INFO] Build completed successfully!

REM Check if executable was created
if exist "Release\ghoststrike.exe" (
    echo [INFO] Executable created: Release\shadowops.exe
    
    REM Get file size
    for %%A in ("Release\shadowops.exe") do set FILE_SIZE=%%~zA
    set /a FILE_SIZE_MB=%FILE_SIZE%/1024/1024
    echo [INFO] File size: %FILE_SIZE_MB% MB
    
    REM Get file version info
    echo [INFO] File version information:
    powershell -Command "Get-ItemProperty 'Release\shadowops.exe' | Select-Object VersionInfo | Format-List"
    
) else (
    echo [ERROR] Executable not found in expected location
    echo [INFO] Checking build directory contents...
    dir /s /b *.exe
)

REM Copy configuration file
echo.
echo [INFO] Setting up configuration...
if exist "..\ghoststrike.conf" (
    copy "..\ghoststrike.conf" "Release\shadowops.conf" >nul
    echo [INFO] Configuration file copied to build directory
) else (
    echo [WARNING] Configuration file not found - creating default...
    echo # ShadowOps Configuration File > "Release\shadowops.conf"
    echo target_process=C:\Windows\explorer.exe >> "Release\shadowops.conf"
    echo enable_logging=true >> "Release\shadowops.conf"
    echo enable_evasion=true >> "Release\shadowops.conf"
)

REM Create sample payload file if it doesn't exist
if not exist "Release\payload.bin" (
    echo [INFO] Creating sample payload file...
    echo This is a sample payload file for testing purposes. > "Release\payload.bin"
echo Replace this with your actual payload before deployment. >> "Release\payload.bin"
echo Generated on: %date% %time% >> "Release\payload.bin"
echo ShadowOps v2.0.0 - https://github.com/Kumarabhijeet1608/ShadowOps >> "Release\payload.bin"
)

REM Run basic tests if available
echo.
echo [INFO] Running basic validation tests...
if exist "Release\ghoststrike.exe" (
    echo [INFO] Testing executable...
    "Release\ghoststrike.exe" --help >nul 2>&1
    if %errorLevel% == 0 (
        echo [INFO] Executable test passed
    ) else (
        echo [WARNING] Executable test failed - this may be expected for security tools
    )
)

REM Create deployment package
echo.
echo [INFO] Creating deployment package...
if exist "Release\ghoststrike.exe" (
    if not exist "deploy" mkdir deploy
    
    REM Copy files to deployment directory
    copy "Release\shadowops.exe" "deploy\" >nul
    copy "Release\shadowops.conf" "deploy\" >nul
    copy "Release\payload.bin" "deploy\" >nul
    copy "..\README.md" "deploy\" >nul
    copy "..\LICENSE" "deploy\" >nul
    
    REM Create batch file for easy execution
    echo @echo off > "deploy\run_shadowops.bat"
    echo echo Starting ShadowOps... >> "deploy\run_shadowops.bat"
    echo shadowops.exe >> "deploy\run_shadowops.bat"
    echo pause >> "deploy\run_shadowops.bat"
    
    echo [INFO] Deployment package created in 'deploy' directory
)

REM Display build summary
echo.
echo ===================================================
echo ⚔️ BUILD SUMMARY ⚔️
echo ===================================================
echo [SUCCESS] ShadowOps v2.0.0 built successfully!
echo.
echo Build Details:
echo - Compiler: %COMPILER%
echo - Build Type: Release
echo - Architecture: x64
echo - Output: Release\shadowops.exe
echo - Configuration: Release\shadowops.conf
echo - Deployment: deploy\ (if created)
echo.
echo Next Steps:
echo 1. Review and modify shadowops.conf as needed
echo 2. Replace payload.bin with your actual payload
echo 3. Test in a controlled environment
echo 4. Deploy to target systems
echo.
echo ⚠️  IMPORTANT: This tool is for educational and authorized testing only!
echo ⚠️  Ensure compliance with all applicable laws and regulations.
echo.
echo ===================================================
echo.

REM Return to original directory
cd ..

echo [INFO] Build script completed successfully!
echo [INFO] Press any key to exit...
pause >nul
