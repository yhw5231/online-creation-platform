#!/bin/sh
# 容器入口脚本：以 root 启动自愈数据目录权限，再降权到非 root 用户运行应用，
# 保证 bind-mount 的宿主 ./data 目录无论属主是谁，部署后都无需手动设置即可使用。
set -e

# 1) 确保数据目录存在（bind-mount 或全新创建均可）
mkdir -p /app/data

# 2) 修正数据目录属主为应用用户（UID 1000），自愈宿主目录权限
chown -R app:app /app/data
chmod 700 /app/data

# 3) 降权到非 root 用户，执行应用主程序
exec su-exec app:app /app/main