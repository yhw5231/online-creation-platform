@echo off
setlocal
rem Local build script: read the version from the VERSION file first (aligned
rem with CI releases), falling back to the latest git tag, then dev version.
rem Windows: produces app.exe. Linux/macOS: use build.sh (produces app).
set "VERSION="
set "VFILE=%TEMP%\ocp_version.tmp"
if exist VERSION set /p FILE_VER=<VERSION
if defined FILE_VER set "VERSION=v%FILE_VER%"
if not defined VERSION git describe --tags --abbrev=0 > "%VFILE%" 2>nul
if not defined VERSION (
    if exist "%VFILE%" set /p VERSION=<"%VFILE%"
)
if not defined VERSION set "VERSION=v0.0.0-dev"
if exist "%VFILE%" del "%VFILE%" >nul 2>nul
set CGO_ENABLED=0
go build -trimpath -ldflags "-s -w -X main.AppVersion=%VERSION%" -o app.exe .
if errorlevel 1 exit /b 1
echo built app.exe (version %VERSION%)
endlocal