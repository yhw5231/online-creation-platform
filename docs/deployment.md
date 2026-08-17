# 在线创作平台 - 完整部署指南

本文档覆盖从拉取代码、环境准备、构建、配置、启动到管理后台初始化的全部部署步骤，适用于 **Linux / Windows / macOS** 服务器与个人电脑。

---

## 目录

1. [前置要求](#1-前置要求)
2. [拉取代码](#2-拉取代码)
3. [部署方式一：Docker 部署（推荐）](#3-部署方式一docker-部署推荐)
4. [部署方式二：源码编译部署](#4-部署方式二源码编译部署)
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
docker compose up -d --build
```

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

- 数据持久化：`./data`（SQLite 数据库、生成的图片）与 `./static` 为 bind-mount 挂载，**删除容器不会丢数据**。
- 容器以非 root 用户（UID 1000）运行，宿主目录需允许 UID 1000 写入：
  ```bash
  mkdir -p data static
  sudo chown -R 1000:1000 data static
  # 若不处理，日志出现 WARN: cannot persist session key ... 时请显式设置 SESSION_SECRET（见 3.1）
  ```
- 容器内置健康检查（30s 间隔），`restart: unless-stopped` 保证开机自启与异常自动重启。

---

## 4. 部署方式二：源码编译部署

### 4.1 准备目录与构建

```bash
# 在项目根目录（已 clone）
# 下载依赖并编译（Windows 上产出 app.exe，Linux/macOS 产出 app）
go mod download
go build -o app .

# 创建运行时目录（数据库与图片）
mkdir -p data static
```

### 4.2 配置环境变量

```bash
# 以 systemd 为例：/etc/systemd/system/online-creation.service
# 先编辑环境变量文件 /etc/online-creation.env：
cat > /etc/online-creation.env <<'EOF'
PORT=8900
SESSION_SECRET=请替换为至少16位的随机字符串
COOKIE_SECURE=false
TRUST_PROXY_HEADERS=false
TZ=Asia/Shanghai
EOF
chmod 600 /etc/online-creation.env   # 含密钥，仅 root 可读
```

### 4.3 注册 systemd 服务（Linux）

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

### 4.4 验证

```bash
sudo systemctl status online-creation   # active (running)
curl http://127.0.0.1:8900/health       # {"status":"ok"}
sudo journalctl -u online-creation -f   # 查看日志
```

> 直接前台运行验证（临时）：`SESSION_SECRET=xxx ./app`，Ctrl+C 停止。

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
| 是否需要注册码 | 开启后需输入兑换码才能注册（可在「兑换码生成」中批量生产） |
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

```bash
cd online-creation-platform

# 拉取最新代码
git pull

# Docker 方式
docker compose up -d --build

# 源码方式
go build -o app . && sudo systemctl restart online-creation
```

> 数据库结构兼容已有数据，升级不丢数据；升级前建议先备份 `data/`（见 9.1）。

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