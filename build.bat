@echo off
setlocal
rem Local build script: derive the version from the latest git tag and inject
rem it into the binary, avoiding the default v1.0.0 after a release.
rem Windows: produces app.exe. Linux/macOS: use build.sh (produces app).
set "VERSION=v0.0.0-dev"
set "VFILE=%TEMP%\ocp_version.tmp"
git describe --tags --abbrev=0 > "%VFILE%" 2>nul
if exist "%VFILE%" (
    set /p VERSION=<"%VFILE%"
    del "%VFILE%" >nul 2>nul
)
set CGO_ENABLED=0
go build -trimpath -ldflags "-s -w -X main.AppVersion=%VERSION%" -o app.exe .
if errorlevel 1 exit /b 1
echo built app.exe (version %VERSION%)
endlocal