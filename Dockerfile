FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

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