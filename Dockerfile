FROM golang:1.21-alpine AS builder
WORKDIR /app
# APP_VERSION 由 CI 通过 --build-arg 注入（如 v1.0.1），与仓库 VERSION 文件、
# main.go 内置默认值保持一致；避免镜像内版本号恒为默认 v1.0.0，导致
# "强拉镜像升级后版本号不变"的版本漂移。本地 docker build 未传参时，
# 自动回退读取仓库根目录 VERSION 文件。
ARG APP_VERSION=dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN if [ "$APP_VERSION" = "dev" ] && [ -f VERSION ]; then APP_VERSION="v$(cat VERSION)"; fi \
    && go build -trimpath -ldflags "-s -w -X main.AppVersion=${APP_VERSION}" -o main .

FROM alpine:latest
# su-exec 用于从 root 降权到应用用户执行主程序
RUN apk add --no-cache su-exec
WORKDIR /app
COPY --from=builder /app/main .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# 预创建数据目录并创建非 root 应用用户（UID 1000）
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && mkdir -p data \
    && addgroup -S app && adduser -S -G app -u 1000 app \
    && chown -R app:app /app
EXPOSE 8900
# 以 root 启动入口脚本：自愈数据目录权限后自动降权运行（见 entrypoint.sh）
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]