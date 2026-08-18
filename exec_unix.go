//go:build linux || darwin

package main

import "syscall"

// execSelf 用新二进制替换当前进程映像（Linux/macOS 上可用）。
// 容器部署时应用进程是 PID 1：直接替换映像后容器不会退出、无需重建，
// Docker 看到同一 PID 持续存活，更新立即生效。
func execSelf(exePath string, args []string, env []string) error {
	return syscall.Exec(exePath, args, env)
}
