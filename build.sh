#!/bin/sh
# 本地构建脚本：自动从 git 最新标签推导版本号并注入二进制
# （避免出现"发布了 vX.Y.Z，但系统内仍显示默认 v1.0.0"的版本漂移）。
# 用法：在项目根目录执行 ./build.sh（Linux / macOS 产出 app；
#       Windows 请使用 build.bat 产出 app.exe）。
set -e

VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0-dev")

CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.AppVersion=${VERSION}" -o app .
echo "built app (version ${VERSION})"