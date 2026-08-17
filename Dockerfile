FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
# 运行时数据目录（SQLite 数据库、生成的图片）：data/ 被 .gitignore 忽略，不会进入构建上下文，
# 由程序启动时自动创建；此处预创建并定向到 UID 1000，配合 compose bind-mount 的宿主 ./data
RUN mkdir -p data \
    # 以非 root 用户运行，降低容器逃逸风险；固定 UID 1000，便于宿主 bind-mount 权限对齐
    && addgroup -S app && adduser -S -G app -u 1000 app \
    && chown -R app:app /app
USER app
EXPOSE 8900
CMD ["./main"]