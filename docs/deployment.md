# 在线创作平台 - 完整部署指南

本文档覆盖从拉取代码、环境准备、构建、配置、启动到管理后台初始化的全部部署步骤，适用于 **Linux / Windows / macOS** 服务器与个人电脑。

---

## 目录

1. [前置要求](#1-前置要求)
2. [拉取代码](#2-拉取代码)
3. [部署方式一：Docker 部署（推荐）](#3-部署方式一docker-部署推荐)
4. [部署方式二：原生二进制部署（无需 Docker，支持 Windows / macOS / Linux）](#4-部署方式二原生二进制部署无需-docker支持-windows--macos--linux)
5. [环境变量配置](#5-环境变量配置)
6. [首次启动与初始化](#6-首次启动与初始化)
7. [管理后台部署设置](#7-管理后台部署设置)
8. [反向代理与 HTTPS](#8-反向代理与-https)
9. [日常运维](#9-日常运维)
10. [升级更新](#10-升级更新)
11. [故障排查](#11-故障排查)
12. [安全加固建议](#12-安全加固建议)

---

## 1. 前置要求

### 服务器要求

| 项目 | 最低要求 | 建议 |
|------|----------|------|
| 系统 | Linux x86_64 / arm64（Docker 或 Go） | Ubuntu 22.04+ / Debian 12+ / CentOS 9+ |
| 内存 | 512 MB | 1 GB+（图片生成任务为异步，内存占用低） |
| 磁盘 | 1 GB | 10 GB+（生成的图片会持续占用磁盘） |
| 网络 | 可访问外网 | 需访问图片生成 API 与 GitHub |

### 二选一准备运行环境

- **Docker 方式**：安装 Docker Engine 20.10+ 与 Docker Compose v2。
  ```bash
  # Ubuntu / Debian
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  docker compose version   # 确认 compose v2
  ```
- **源码方式**：安装 Go 1.21 或更高版本。
  ```bash
  # 下载安装 Go（以 linux-amd64 为例）
  wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
  sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  source ~/.bashrc
  go version   # 确认输出 go1.21+
  ```

> 域名与 HTTPS 证书（可选）：如需公网域名访问与 HTTPS，准备解析好的域名及 Nginx / Caddy；平台本身监听 HTTP，HTTPS 由反向代理终止（见[第 8 节](#8-反向代理与-https)）。

---

## 2. 拉取代码

```bash
# 方式一：HTTPS
git clone https://github.com/yhw5231/online-creation-platform.git
cd online-creation-platform

# 方式二：SSH（服务器已配置 GitHub SSH Key 时）
git clone git@github.com:yhw5231/online-creation-platform.git
cd online-creation-platform
```

拉取后目录结构（其余为源码文件）：

```
├── main.go            # 服务入口与全部处理器
├── models/            # 数据库模型、连接、配置
├── services/grok.go   # Grok 图片生成 API 客户端
├── templates/         # HTML 模板（前台 + 管理后台）
├── static/            # CSS / JS / 图标
├── data/              # SQLite 数据库与生成的图片（运行时自动创建）
├── docker-compose.yml # Docker 编排（Docker 方式使用）
└── Dockerfile         # 镜像构建（Docker 方式使用）
```

---

## 3. 部署方式一：Docker 部署（推荐）

### 3.1 配置环境变量

在项目根目录创建 `.env` 文件（Docker Compose 自动读取），**务必修改 `SESSION_SECRET`**：

```bash
# .env 文件内容
# 监听端口（容器内外均可访问的宿主端口）
PORT=8900

# 会话签名密钥：至少 16 位随机字符串，用于签名会话 Cookie。
# 可用命令生成：openssl rand -hex 32
SESSION_SECRET=请替换为至少16位的随机字符串

# HTTPS 部署时设为 true（见第 8 节）
COOKIE_SECURE=false

# 反向代理部署时设为 true，登录限流改用 X-Forwarded-For 真实 IP
TRUST_PROXY_HEADERS=false

# 时区
TZ=Asia/Shanghai
```

### 3.2 构建并启动

```bash
docker compose up -d
```

> 默认直接拉取 **GitHub Actions 自动构建发布的官方镜像**（`ghcr.io/yhw5231/online-creation-platform`，同时发布 linux/amd64 与 linux/arm64）。
> 首次会从 GHCR 拉取，之后每次 `docker compose up -d` 都会自动检查并拉取最新镜像（`pull_policy: always`）。
>
> 若确需在服务器本地从源码构建（不推荐，升级需手动拉代码+构建）：编辑 `docker-compose.yml`，注释 `image` 行并取消 `build: .` 注释，再执行 `docker compose up -d --build`。

### 3.3 验证

```bash
# 查看容器状态与日志
docker compose ps
docker compose logs -f

# 健康检查（返回 {"status":"ok"} 即正常）
curl http://127.0.0.1:8900/health

# 浏览器访问
# http://服务器IP:8900
```

### 3.4 Docker 方式注意事项

- 数据持久化：仅 `./data`（SQLite 数据库、生成的图片）为 bind-mount 挂载，**删除容器不会丢数据**；静态资源与模板已打包进镜像，升级自动同步，无需再挂载 `./static`。
- 容器以非 root 用户（UID 1000）运行，宿主目录需允许 UID 1000 写入：
  ```bash
  mkdir -p data
  sudo chown -R 1000:1000 data
  # 若不处理，日志出现 WARN: cannot persist session key ... 时请显式设置 SESSION_SECRET（见 3.1）
  ```
- 容器内置健康检查（30s 间隔），`restart: unless-stopped` 保证开机自启与异常自动重启。

---

## 4. 部署方式二：原生二进制部署（无需 Docker，支持 Windows / macOS / Linux）

> **适用场景**：未安装 Docker 的 Windows / macOS / Linux 电脑直接运行。
> **获取方式**：GitHub Releases 页面（`https://github.com/yhw5231/online-creation-platform/releases`）下载对应平台的压缩包：
>
> | 文件 | 适用平台 |
> |------|---------|
> | `online-creation-windows-amd64.zip` | Windows 10/11（Intel/AMD 64 位），解压后运行 `app.exe` |
> | `online-creation-windows-arm64.zip` | Windows ARM64（如骁龙笔记本） |
> | `online-creation-darwin-amd64.tar.gz` | macOS（Intel 芯片） |
> | `online-creation-darwin-arm64.tar.gz` | macOS（Apple 芯片 M1/M2/M3…） |
> | `online-creation-linux-amd64.tar.gz` | Linux x86_64（同容器镜像架构，无需 Docker） |
> | `online-creation-linux-arm64.tar.gz` | Linux ARM64（如树莓派） |
>
> 压缩包内含可执行文件 `app`（Windows 为 `app.exe`）+ `templates/` + `static/`，解压后按以下步骤运行（自动完成构建、下载依赖，无需安装 Go）。

### 4.1 解压并配置

```bash
# 以 macOS / Linux 为例（Windows 解压 zip 后同理，在项目目录内执行）
tar -xzf online-creation-darwin-arm64.tar.gz
cd online-creation-darwin-arm64   # 解压出的目录，内含 app / templates / static
mkdir -p data static
```

按第 5 节配置环境变量（Windows 用 `set` 或系统环境变量代替 `export`）。

### 4.2 启动

```bash
# macOS / Linux —— 首次运行 mac 二进制需授予执行权限
chmod +x app
SESSION_SECRET=至少16位随机串 ./app

# Windows —— 在解压目录内，PowerShell：
# $env:SESSION_SECRET="至少16位随机串"; .\app.exe
```

默认监听 `:8900`，浏览器访问 `http://127.0.0.1:8900`；健康检查同 3.3 节。

### 4.3 注意事项

- 原生二进制为**独立可执行文件**，不依赖 Docker / Go 环境；数据库与图片同样保存在 `data/`。
- 后台常驻建议用系统服务：Linux 见下方 4.4 systemd 示例；Windows 可用「任务计划程序」或 NSSM 注册服务；macOS 可用 launchd。
- `static/` 随包提供，如需自定义样式直接修改解压目录中的文件。

### 4.4 systemd 服务（Linux 原生二进制）

```bash
cat > /etc/systemd/system/online-creation.service <<'EOF'
[Unit]
Description=Online Creation Platform
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/online-creation-platform
EnvironmentFile=/etc/online-creation.env
ExecStart=/opt/online-creation-platform/app
Restart=always
RestartSec=5
# 以普通用户运行（建议单独建用户）
User=appuser

[Install]
WantedBy=multi-user.target
EOF

# 假设部署目录与用户：
# sudo useradd -r -s /usr/sbin/nologin appuser
# sudo chown -R appuser:appuser /opt/online-creation-platform

sudo systemctl daemon-reload
sudo systemctl enable --now online-creation
```

### 4.5 验证

```bash
sudo systemctl status online-creation   # active (running)
curl http://127.0.0.1:8900/health       # {"status":"ok"}
sudo journalctl -u online-creation -f   # 查看日志
```

> 直接前台运行验证（临时）：`SESSION_SECRET=xxx ./app`，Ctrl+C 停止。

### 4.6 源码编译部署（本地开发 / 有 Go 环境时）

```bash
# 在项目根目录（已 clone），仅需 Go 1.21+，无需 Docker
go mod download
./build.sh                 # 自动从 git 最新标签推导版本号注入二进制，产出 app
                           # （Windows 用 build.bat，产出 app.exe；无标签时版本为 v0.0.0-dev）
mkdir -p data static
SESSION_SECRET=xxx ./app # 或 Windows: $env:SESSION_SECRET="xxx"; .\app.exe
```

> 版本号说明：`main.AppVersion` 默认值为 `v1.0.0`，只有通过 `-ldflags "-X main.AppVersion=vX.Y.Z"` 注入才是真实版本。CI 发布（打 v 标签）时自动注入；本地构建请使用 `build.sh` / `build.bat`，脚本会从最近一次 git 标签自动推导版本号，避免系统内版本号与发布版本不一致。

与 4.1~4.5 的原生二进制运行方式相同，区别仅是自行编译产物，适合本地调试与二次开发。

---

## 5. 环境变量配置

| 变量 | 说明 | 默认 |
|------|------|------|
| `PORT` | 监听端口 | `8900` |
| `SESSION_SECRET` | 会话签名密钥（建议 ≥16 位随机串）。不设置时首次启动自动生成随机密钥并存入 `data/.session_secret` 复用；**已部署实例更换密钥会使所有已登录会话失效** | 自动生成 |
| `COOKIE_SECURE` | 设为 `true` 时仅通过 HTTPS 下发会话 Cookie（未配 HTTPS 时勿开，会导致登录不生效） | `false` |
| `TRUST_PROXY_HEADERS` | 反向代理部署时设为 `true`，登录限流改用 `X-Forwarded-For` 真实客户端 IP（防代理后所有人共享一个 IP 被一起锁死） | `false` |
| `TZ` | 时区（Docker 环境变量中已默认 `Asia/Shanghai`） | 系统时区 |

---

## 6. 首次启动与初始化

1. **启动服务**（任选第 3 / 4 节方式）。
2. 首次启动自动完成：
   - 创建 SQLite 数据库 `data/creation.db`；
   - 创建默认管理员 `admin / admin123`（日志输出 `No admin user found. Creating default admin`）。
3. **立即修改默认密码**：浏览器访问首页 → 登录 `admin / admin123` → 右上角头像菜单 →「修改密码」。
4. 访问管理后台：登录后点击头像菜单 →「管理后台」（或直接访问 `/admin`）。
5. 健康检查：`curl http://127.0.0.1:8900/health` 返回 `{"status":"ok"}`。

---

## 7. 管理后台部署设置

登录 admin 进入 **管理后台（/admin）**，按以下顺序完成上线前设置：

### 7.1 基本信息
| 设置项 | 说明 |
|--------|------|
| 站点名称 | 显示在浏览器标题与页脚 |
| 单张消耗积分 | 每次生成 1 张图片扣除的积分 |

### 7.2 注册设置
| 设置项 | 说明 |
|--------|------|
| 开放注册 | 关闭后仅管理员可手动在后台开通用户 |
| 是否需要注册码 | 开启后需输入**注册码**才能注册（在「兑换码管理」中选择「注册码」类型批量生成） |
| 初始积分 | 新用户注册赠送积分 |

### 7.3 签到设置
| 设置项 | 说明 |
|--------|------|
| 开关 | 关闭签到功能 |
| 模式 | 固定（每天固定额度）/ 随机（范围内随机，加密级随机源） |
| 额度范围 | 随机模式下每日签到积分区间 |

### 7.4 图片生成接口（上线前必配）
按行添加生成渠道，每行配置：

| 配置项 | 说明 |
|--------|------|
| 渠道名称 | 创作页下拉框展示的名称 |
| API 地址 | 图片生成接口 URL（格式见 `docs/grok-image-api.md`） |
| API Key | 上游服务密钥 |
| 默认模型 | 该渠道默认使用的模型 |
| NSFW 渠道 | 勾选后：创作页开启 NSFW 时自动走该渠道；普通创作走未勾选渠道 |

> 可添加多个普通渠道 + 一个或多个 NSFW 渠道，创作页自动路由。保存后可在创作页测试生成。

### 7.5 第三方登录（可选）
Linux.do OAuth：在「系统设置 → 第三方登录（Linux.do）」中填写 Client ID / Secret / Redirect URI。设置页会**自动显示本平台的回调地址**（格式如 `https://你的域名/auth/linuxdo/callback`），点击「填入当前地址」或「复制」即可使用；该地址必须与 [Linux.do 开发者后台](https://connect.linux.do)（Linux.do Connect 官网登录后创建应用）中应用的 Callback URL 完全一致，否则授权会失败。Redirect URI 输入框保存后持久化，**留空保存 = 自动模式**：系统每次按当前站点地址动态使用该回调地址，更换域名后无需再改。

> 平台对接的是 Linux.do Connect 标准的 OAuth 2.0 / OpenID Connect 接口（授权 `https://connect.linux.do/oauth2/authorize`、令牌 `https://connect.linux.do/oauth2/token`、用户信息 `https://connect.linux.do/api/user`）。早期版本错误使用了不存在的 `/oauth/*` 路径，导致授权页返回 “Not Found / Please make sure you entered the information correctly”，升级后即可正常登录。

### 7.6 上线前检查清单
- [ ] 已修改默认管理员密码
- [ ] 已配置至少一个图片生成渠道并实测生成成功
- [ ] 已按运营策略配置注册 / 签到 / 消耗积分
- [ ] 已设置 `SESSION_SECRET`（生产环境必须显式设置）
- [ ] 已按需开放注册或启用注册码

---

## 8. 反向代理与 HTTPS

平台自身监听 HTTP，公网部署建议由 Nginx 终止 HTTPS 并转发：

### 8.1 Nginx 配置示例

```nginx
server {
    listen 80;
    server_name 你的域名.com;
    # HTTP 强制跳转 HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name 你的域名.com;

    ssl_certificate     /etc/letsencrypt/live/你的域名.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/你的域名.com/privkey.pem;

    # 图片与静态资源可走更长缓存
    location /static/ {
        proxy_pass http://127.0.0.1:8900;
        proxy_set_header Host $host;
    }

    location / {
        proxy_pass http://127.0.0.1:8900;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;   # 图片转存/下载可能较慢
    }
}
```

### 8.2 配套环境变量

| 变量 | 值 | 原因 |
|------|-----|------|
| `COOKIE_SECURE` | `true` | 仅通过 HTTPS 下发 Cookie |
| `TRUST_PROXY_HEADERS` | `true` | 登录限流使用真实客户端 IP |

> 证书申请（Let's Encrypt）：`sudo apt install certbot python3-certbot-nginx && sudo certbot --nginx -d 你的域名.com`。

---

## 9. 日常运维

### 9.1 数据备份
数据库与图片全部在 `data/` 目录，备份即复制该目录：

```bash
# 建议先停止写入或使用 sqlite3 在线备份
sqlite3 data/creation.db ".backup '/backup/creation-$(date +%F).db'"
cp -r data/images /backup/   # 生成的图片
```

管理后台也提供「一键下载数据库备份」功能（管理后台 → 数据概览）。

### 9.2 日志查看

```bash
# Docker
docker compose logs -f --tail=100
# systemd
journalctl -u online-creation -f
```

### 9.3 数据库手动操作（救援用）

```bash
# 将用户设为管理员
sqlite3 data/creation.db "UPDATE users SET role='admin' WHERE username='目标用户';"
```

---

## 10. 升级更新

### 10.1 半自动：一条命令升级（推荐）

代码推送到 GitHub 后，GitHub Actions 会自动构建新镜像并发布到 GHCR（`latest` + `sha-xxxx` 标签，amd64/arm64）。服务器上只需：

```bash
cd online-creation-platform
docker compose pull    # 拉取最新镜像
docker compose up -d   # 用新镜像重建容器（数据卷不变，不丢数据）
```

> 因为 compose 配置了 `pull_policy: always`，直接 `docker compose up -d` 也会自动拉取最新镜像，`pull` 可省略。

### 10.2 全自动：Watchtower 自动升级

部署 [Watchtower](https://github.com/containrrr/watchtower) 后，每次 GitHub 推送触发新镜像发布时，Watchtower 会自动拉取并原地重建容器，无需任何手动操作：

```bash
docker run -d \
  --name watchtower \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock \
  containrrr/watchtower --interval 60 --cleanup
```

> `--interval 60`：每 60 秒检查一次新镜像；`--cleanup`：自动清理旧镜像。
> 升级前建议先备份 `data/`（见 9.1）。数据库结构兼容已有数据，升级不丢数据。

### 10.3 源码方式部署的升级

```bash
cd online-creation-platform
git pull
go build -o app . && sudo systemctl restart online-creation
```

### 10.4 原生二进制（Windows / macOS）部署的升级

重新下载 GitHub Releases 中的对应平台压缩包，覆盖解压目录后重启服务即可（`data/` 目录保留即不丢数据）：

```bash
# 以 macOS 为例：下载新包 → 解压覆盖 → 重启
tar -xzf online-creation-darwin-arm64.tar.gz --overwrite -C /opt/online-creation-platform
sudo systemctl restart online-creation   # 或直接重启你的服务方式
```

---

## 11. 故障排查

| 现象 | 原因与处理 |
|------|-----------|
| 页面能打开但无法登录 | ① 检查 `SESSION_SECRET` 是否为空（日志 WARN 提示）；② 检查是否误开 `COOKIE_SECURE=true` 且未走 HTTPS，改回 `false` 或配置 HTTPS 后重启 |
| 注册/登录后提示输入框被限流 | 反向代理未设 `TRUST_PROXY_HEADERS=true`，所有用户共用一个 IP 触发锁；或确实连续失败 5 次（锁 10 分钟） |
| 生成任务一直失败 | 检查后台「图片生成接口」渠道的 API 地址 / Key / 模型是否正确；查看日志中的上游错误详情（已裁剪至 300 字符便于排查） |
| 容器日志出现 `cannot persist session key` | 数据目录权限：`sudo chown -R 1000:1000 data`，或显式设置 `SESSION_SECRET` |
| 磁盘空间不足 | 删除无用的创作记录（后台或用户端删除会连带清理本地图片文件），定期清理 `data/images/` |
| 健康检查失败 / 容器反复重启 | `docker compose logs` 查看启动错误；确认 8900 端口未被占用（`ss -lntp \| grep 8900`） |
| 图片生成后预览 404 | 创作记录删除操作会同步删除本地文件；检查 `data/images/` 权限是否为运行用户可读 |

---

## 12. 安全加固建议

1. **修改默认密码**：`admin/admin123` 上线后立即修改。
2. **显式设置 `SESSION_SECRET`**：用 `openssl rand -hex 32` 生成并妥善保管。
3. **HTTPS 全覆盖**：公网必须走反向代理 + 证书，开启 `COOKIE_SECURE=true`。
4. **环境变量文件权限**：含密钥的文件 `chmod 600` 且仅管理用户可读。
5. **数据库与图片目录**：`data/` 不要暴露给 Web 直接访问（本平台仅通过受控路由读取，勿将 data 目录放到 Nginx 静态根下）。
6. **定期备份**：见 [9.1 数据备份](#91-数据备份)。
7. **关注日志**：登录限流日志会记录暴力尝试来源 IP，异常时及时处置。
8. **防爆破/限流（内置）**：登录连续失败 5 次锁定该 IP 10 分钟；登录、注册、积分兑换、修改密码、OAuth 绑定等敏感 POST 均按 IP 滑动窗口限流（默认每 IP 每分钟 10 次，超限返回 429）。反向代理部署时务必设置 `TRUST_PROXY_HEADERS=true`（见第 5 节），否则所有访客共享代理地址、限流会误伤。兑换码/注册码为 32 位随机字符（大写字母+数字，不含易混淆字符），不可枚举，请勿手动缩短。