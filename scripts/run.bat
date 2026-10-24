@echo off
rem ==============================================================================
rem Script Name:   run.bat
rem Description:   Universal launcher for netlog on Windows.
rem Author:        Mai Tan Duc <ducmai.network@gmail.com>
rem Created:       2026-10-23
rem Version:       1.0.0
rem License:       MIT
rem ==============================================================================
rem Usage:         run.bat [options] [arguments]
rem ==============================================================================

set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR%..\"

set BINARY="%ROOT_DIR%bin\netlog.exe"
set ARCH_BINARY="%ROOT_DIR%bin\netlog-windows-amd64.exe"
set ROOT_BINARY="%ROOT_DIR%netlog.exe"
set ROOT_ARCH_BINARY="%ROOT_DIR%netlog-windows-amd64.exe"

if exist %BINARY% goto :run
if exist %ARCH_BINARY% (
    set BINARY=%ARCH_BINARY%
    goto :run
)
if exist %ROOT_BINARY% (
    set BINARY=%ROOT_BINARY%
    goto :run
)
if exist %ROOT_ARCH_BINARY% (
    set BINARY=%ROOT_ARCH_BINARY%
    goto :run
)

echo Binary %BINARY% not found. Building...

where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Error: 'go' is not installed but is required to build the binary.
    echo Please install Go or download a pre-built binary.
    exit /b 1
)

if not exist "%ROOT_DIR%vendor" (
    echo Checking and installing required dependencies...
    pushd "%ROOT_DIR%"
    go mod tidy
    go mod vendor
    popd
)

echo Building binary...
set CGO_ENABLED=0
pushd "%ROOT_DIR%"
go build -mod=vendor -trimpath -ldflags "-s -w" -o "%ROOT_DIR%bin\netlog.exe" .\cmd\netlog
popd
set BINARY="%ROOT_DIR%bin\netlog.exe"

:run
if "%~1"=="" (
    %BINARY% collect
) else if "%~1"=="--dry-run" (
    %BINARY% collect %*
) else if "%~1"=="-dry-run" (
    %BINARY% collect %*
) else (
    %BINARY% %*
)
