---
name: release-guide
description: 指导在线创作平台（online-creation-platform，GitHub 仓库 yhw5231/online-creation-platform）的代码推送与版本发布：本地验证与中文提交、推送到 master 触发 CI 自动发布 Docker 镜像，以及打标签发布原生安装包（GitHub Release）的完整步骤与常见陷阱排查。
whenToUse: 用户要求推送代码、发布版本、打 v 标签、创建或检查 GitHub Release、排查 CI 构建失败或发行版缺失问题时使用。本技能只指导流程与命令，不代替执行。
---

# 推送与发布指南（Push & Release Guide）

本技能指导如何推送 `D:\NET\ai\在线创作平台` 的代码并发布版本。详细规范见仓库 `docs/release.md`，本技能是其可执行摘要。**所有提交与发布操作一律使用中文**。

## 1. 推送代码到 master

推送前必须本地构建并跑通测试：

```bash
go build ./...
go test ./... -count=1
```

提交信息要求：中文、一句话说清楚改动（如 `feat: 创作失败按倍率扣减积分`），不要 `fix bug` 之类的空话。

```bash
git add -A
git commit -m "feat: <中文描述>"
git pull --rebase origin master   # 先同步远程，避免非快进
git push origin master
```

推送后 CI（`.github/workflows/docker-publish.yml`）自动完成三件事：
1. 把 `VERSION` 文件补丁号 +1（如 1.3.5 → 1.3.6），同步改 `main.go` 内置版本号，以 `[skip ci]` 提交回仓库并尽力打 `vX.Y.Z` 标签；
2. 构建并发布 ghcr.io 镜像（`latest` + `vX.Y.Z` 两个标签）。

服务器升级：`docker compose pull && docker compose up -d`。

## 2. 发布原生安装包（GitHub Release）

Docker 镜像自动发布，**无需打标签**；只有需要 Windows/macOS/Linux 原生安装包时才发布 Release。

### 步骤 A：等 CI 升级版本号并同步本地

推送后等 2~5 分钟，拉取 CI 的版本号升级提交。**必须在升级后的提交上打标签**：

```bash
git fetch origin
git show origin/master:VERSION    # 确认已升级，例如输出 1.3.6
git merge --ff-only origin/master  # 本地必须同步，否则标签指向旧提交
```

### 步骤 B：打标签并推送

标签版本必须与 `VERSION` 文件完全一致（CI 强校验，不一致构建直接失败）。

```bash
git tag v1.3.6          # 版本号以 VERSION 文件内容为准
git push origin v1.3.6
```

> **关键**：CI 自动打的标签由 GITHUB_TOKEN 推送，**不会触发 build-binaries.yml**，必须由本人（用户账号）重新推送同名标签才会触发原生构建。

### 步骤 C：验证构建并确认 Release

```bash
gh run list --workflow=build-binaries.yml --limit 2
gh run watch <run-id> --exit-status
gh release list --limit 3
```

若 `gh run list` 没有出现新 run（常见原因：删除标签后立即重建同名标签，GitHub 不投递 push 事件），用手动派发触发：

```bash
gh workflow run build-binaries.yml --ref v1.3.6
```

## 3. 常见陷阱排查表

| 陷阱 | 现象 | 正确做法 |
| --- | --- | --- |
| 本地未同步远程就打标签 | 构建失败：`发布标签 vX.Y.Z 与仓库文件内版本号 vX.Y.Z-1 不一致` | 先 `git fetch` + `git merge --ff-only origin/master`，在版本号升级提交上重新打标签 |
| CI 自动标签不触发原生构建 | 标签存在但 GitHub Release 没有新版本 | 删除远程标签后由本人重新推送：`git push origin :refs/tags/v1.3.6` 再 `git push origin v1.3.6`；或直接手动派发工作流 |
| 删除后重建同名标签不触发 | `git push origin v1.3.6` 成功但 Actions 无新 run | GitHub 不投递该 push 事件，改用 `gh workflow run build-binaries.yml --ref v1.3.6` |
| 版本号升级提交未出现 | `git show origin/master:VERSION` 仍是旧版本 | 等 CI 完成（约 2~5 分钟），重新 `git fetch origin` |
| Release 说明不完整 | 只有自动生成的 "Full Changelog" | 在 GitHub Releases 页面手工补充中文逐条变动说明 |

## 4. 边界与注意

- 不要手动修改 `VERSION` 或 `main.go` 版本号——由 CI 自动升级；本地构建请用 `build.bat` / `build.sh`（读取 VERSION 注入版本号），不要直接 `go build`。
- 打标签只能在 `master` 分支、且与远程同步后进行；推送标签前先确认 `git rev-parse HEAD` 与 `origin/master` 一致。
- 发布说明必须中文、逐条写明本次变动（禁止删除变动清单只留 "Full Changelog"）。
- 补丁发布：先推 master 升级版本号，再打新标签，不要在已有 Release 上覆盖。