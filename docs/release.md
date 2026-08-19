# 推送与版本发布规范

本仓库的协作约定：**推送、版本发布一律使用中文**，且版本发布必须**详细写明本次变动内容**，禁止只添加自动生成的 "Full Changelog"。

## 一、提交（推送）要求

1. **提交信息使用中文**，一句话说清楚本次改了什么（允许少量英文技术词，如 fix/feat 前缀可保留英文单词，但说明主体必须是中文）。
   - 好：`修复创作记录累计消耗统计失败退回积分`
   - 好：`feat: 设置页增加在线检测新版本与在线更新`
   - 不好：`fix bug`、`update`、`misc changes`
2. 每个提交只做一件事，避免把无关改动混在一个提交里，便于后续自动汇总发布说明。
3. 推送前先本地构建并跑通测试：`go build ./... && go test ./...`。
4. **版本号完全自动化，无需手动修改**：每次推送到 master，CI 自动把仓库根目录 `VERSION` 文件（唯一版本来源）的补丁号 +1（如 `1.0.0 → 1.0.1`），同步更新 `main.go` 内置默认版本号，并提交回仓库（`[skip ci]`）、尽力打 `vX.Y.Z` 标签，然后用该版本号构建并发布 ghcr.io 镜像（`latest` + `vX.Y.Z`）。
   - **效果**：每次推送后服务器 `docker compose pull && docker compose up -d` 拉取的新镜像，设置页"关于与更新"中的版本号都会随之 +1，不再固定显示 `v1.0.0`。

## 二、原生安装包发布要求（打 v 标签）

Docker 镜像在每次推送 master 时自动发布，**无需打标签**；只有需要发布 Windows / macOS / Linux 原生安装包（GitHub Release）时才打标签：

1. 版本号格式：`vX.Y.Z`（如 `v1.0.1`）。**标签版本号必须与仓库文件内版本号（`VERSION` 文件内容）完全一致**，CI 会强校验，不一致直接构建失败——因为每次推送 master 已自动升级版本号，所以直接打当前 `VERSION` 对应的标签即可（例：`VERSION` 为 `1.0.3` 则打 `git tag v1.0.3 && git push origin v1.0.3`）。
2. 打标签后 GitHub Actions 自动执行 `build-binaries.yml`：交叉编译各平台原生安装包，把版本号注入可执行文件（`-X main.AppVersion=vX.Y.Z`，设置页"关于与更新"读取并用于**在线检测新版本 / 在线更新**）。
3. **发布说明必须详细、中文、逐条写明本次变动内容**。CI 会自动从"上一个标签 → 当前标签"之间的全部提交汇总成"更新内容"清单；发布前请在 GitHub Releases 页面手工补充/校验说明（例如：升级注意事项、配置文件变更、数据库变更、需要管理员重新设置的项目）。**禁止删除变动清单而只保留 "Full Changelog"。**
4. 若发布后发现重大缺陷需要补丁：先推送到 master 自动升级版本号（或等待下一次推送），再打与 `VERSION` 一致的新标签发布，不要在已有 Release 上直接覆盖安装包。

## 三、原生发布的完整操作步骤（含陷阱排查）

> 以下为 v1.3.6 发布时踩坑总结出的**正确流程**，发布前请按此顺序执行。

### 步骤 1：推送代码到 master

```bash
# 本地先验证
go build ./... && go test ./...
# 中文提交（见第一节要求）
git add -A && git commit -m "feat: ..."
git pull --rebase origin master
git push origin master
```

推送后 CI（docker-publish.yml）会自动：升级 `VERSION` 补丁号 +1 → 回写 `[skip ci]` 提交 → 打 `vX.Y.Z` 标签（GITHUB_TOKEN）→ 构建并发布 ghcr.io 镜像（latest + vX.Y.Z）。

### 步骤 2：等待版本号升级完成并同步本地

CI 自动升级版本号需要几分钟。**必须**拉取远程，否则本地打标签会指向旧提交：

```bash
git fetch origin
git show origin/master:VERSION   # 确认已升级，如 1.3.6
git merge --ff-only origin/master
```

### 步骤 3：以本人身份打标签并推送

> ⚠️ **关键**：CI 自动打的标签由 GITHUB_TOKEN 推送，**不会触发 build-binaries.yml**（GitHub 安全机制）。原生发布必须由本人重新推送同名标签。

```bash
git tag v$(Get-Content VERSION)   # 或 v1.3.6
git push origin v1.3.6
```

### 步骤 4：验证构建是否触发

```bash
gh run list --workflow=build-binaries.yml --limit 2
```

- ✅ 若出现新的 push 触发的 run：等待其完成，`gh run watch <run-id>`，完成后 `gh release list` 确认。
- ⚠️ **若没有出现新 run**（可能原因：删除后立即重建同名标签，GitHub 不投递 push 事件），手动派发：

```bash
gh workflow run build-binaries.yml --ref v1.3.6
gh run watch <新 run-id> --exit-status
```

### 常见陷阱（v1.3.6 发布实测）

| 陷阱 | 现象 | 正确做法 |
| --- | --- | --- |
| 本地未同步远程就打标签 | 构建失败：`发布标签 vX.Y.Z 与仓库文件内版本号 vX.Y.Z-1 不一致` | 先 `git fetch && git merge --ff-only origin/master`，在版本号升级提交上打标签 |
| CI 自动打的标签不触发原生构建 | 标签存在但 `gh release list` 没有新 Release | 删除远程标签后由本人重新推送，或直接 `gh workflow run build-binaries.yml --ref vX.Y.Z` |
| 删除标签后立即重建同名标签 | `git push origin vX.Y.Z` 成功但 Actions 无任何新 run | GitHub 不投递 push 事件；改用 `workflow_dispatch` 手动触发 |
| 发布说明不完整 | Release 只有 "Full Changelog" | 在 Releases 页面补充中文逐条变动说明（见第一节） |



- 仓库根目录 `VERSION` 文件是**唯一版本来源**；`main.go` 内置默认版本号由 CI 每次推送时同步升级，保证源码内版本号与发布版本一致。
- **本地构建请使用 `build.sh` / `build.bat`**：脚本优先从 `VERSION` 文件读取版本号注入二进制，无 `VERSION` 文件时回退到最近 git 标签 / 开发版本号；不要手动 `go build`，否则会显示源码内的默认版本号与发布版本不一致。
- 设置页 → 系统设置 → 关于与更新：展示当前版本、在线检测 GitHub Releases 最新版、按当前平台（GOOS/GOARCH）匹配安装包并在线更新：
  - **原生二进制部署**（Windows / macOS / Linux 直接运行 app）：替换文件后自动重启；
  - **容器部署**：替换文件后在当前容器内原地重启（应用进程是容器 PID 1，用进程映像替换实现，容器不退出、立即生效）。**注意**：容器重建（`docker compose up -d` / 重启服务器）后会恢复镜像版本，持久升级请执行 `docker compose pull && docker compose up -d`，或配置 Watchtower 全自动升级。
- 因此安装包文件名必须保持 CI 约定：`online-creation-<os>-<arch>.(zip|tar.gz)`，不要手工改名，否则在线更新将无法匹配到文件。