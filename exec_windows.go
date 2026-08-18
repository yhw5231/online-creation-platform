//go:build windows

package main

import "errors"

// execSelf 在 Windows 上不支持进程映像替换（Windows 无 execve），
// 直接返回错误；Windows 更新走 do-update.cmd 脚本流程。
func execSelf(exePath string, args []string, env []string) error {
	return errors.New("windows 不支持进程映像替换")
}
