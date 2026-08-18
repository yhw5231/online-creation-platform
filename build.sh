#!/bin/sh
# 本地构建脚本：优先从 VERSION 文件读取版本号并注入二进制（与 CI 发布版本、
# 文件内版本号保持一致）；无 VERSION 文件时回退为最近 git 标签，再回退为
# 开发版本号。用法：在项目根目录执行 ./build.sh（Linux / macOS 产出 app；
#       Windows 请使用 build.bat 产出 app.exe）。
set -e

if [ -f VERSION ]; then
    VERSION="v$(cat VERSION)"
else
    VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0-dev")
fi

CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.AppVersion=${VERSION}" -o app .
echo "built app (version ${VERSION})"