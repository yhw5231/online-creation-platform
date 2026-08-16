# 在线创作平台 - API 接口文档

通过 API Key 调用生成图片接口，积分扣减规则与网页完全相同。本平台默认监听 `:8900`（可用环境变量 `PORT` 覆盖）。

## 目录

1. [获取 API Key](#1-获取-api-key)
2. [认证方式](#2-认证方式)
3. [生成图片（异步任务）](#3-生成图片异步任务)
4. [查询任务状态](#4-查询任务状态)
5. [curl 完整示例](#5-curl-完整示例)
6. [错误码](#6-错误码)
7. [积分与配额说明](#7-积分与配额说明)
8. [常见问题](#8-常见问题)

## 1. 获取 API Key

登录平台进入 **个人主页（/profile）** →「API Key」卡片 → 点击「生成 API Key」。

- 新 Key 明文**仅显示一次**，请立即复制保存；数据库只保存 Key 的 SHA-256 哈希，无法找回明文。
- 随时可以「刷新 Key」：旧 Key 立即失效，生成的新 Key 同样仅显示一次。
- 每个用户同时只有一个有效的 API Key。

## 2. 认证方式

所有受保护接口在请求头携带 Key，二选一：

```
Authorization: Bearer sk-xxxxxxxx
```

或：

```
X-API-Key: sk-xxxxxxxx
```

- Key 缺失：返回 `401`，错误内容 `{"ok":false,"error":"missing api key"}`
- Key 无效或对应用户已被禁用：返回 `401`，错误内容 `{"ok":false,"error":"invalid api key"}`

## 3. 生成图片（异步任务）

### 请求

`POST /api/v1/generate`

请求头：

```
Authorization: Bearer sk-xxxxxxxx
Content-Type: application/json
```

请求体（JSON）：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `prompt` | string | 是 | 提示词，最长 4000 字（UTF-8 按字符数计） |
| `channel` | string | 否 | 渠道下标字符串（从 0 开始，如 `"0"`、`"1"`），留空自动选第一个普通渠道；渠道无效返回 400 |
| `n` | int | 否 | 生成数量，1–4，默认 1；超出范围自动收敛到 1–4 |
| `aspect_ratio` | string | 否 | 宽高比：`1:1` / `16:9` / `4:3` / `3:4` / `9:16` / `21:9`，默认 `1:1` |
| `resolution` | string | 否 | 分辨率档位（如 `1k`/`2k`/`4k`），**必须为该渠道支持的档位**，默认取渠道第一个档位；渠道不支持时返回 400 并列出支持的档位 |

> 注意：`channel` 是**字符串类型**，传数字（如 `0`）会导致整包 JSON 解析失败返回 `400 invalid json`。
> 返回格式由系统后台自适应固定（URL），请求体中**不需要**（也不接受）`response_format` 字段。

示例：

```json
{"prompt": "一只猫，在窗台晒太阳", "channel": "0", "n": 2, "aspect_ratio": "1:1", "resolution": "2k"}
```

### 响应（成功）

```json
{"ok": true, "task_id": 123, "message": "任务已提交"}
```

- 任务为**异步**处理：提交成功立即返回，图片在后台生成。
- 积分在提交时按 `n × 单张费用` **条件扣减**（余额不足不扣减并返回 402）。
- 单张费用等于系统设置中的「消耗积分 / 次」（网页与 API 一致）。

## 4. 查询任务状态

### 请求

`GET /api/v1/status?task_id=123`

请求头：

```
Authorization: Bearer sk-xxxxxxxx
```

### 响应（成功）

```json
{
  "ok": true,
  "task_id": 123,
  "status": "success",
  "prompt": "一只猫",
  "images": ["/images/xxx.png"],
  "error": "",
  "created_at": "2026-08-16T12:00:00+08:00"
}
```

字段说明：

- `status`：`processing`（生成中）/ `success`（成功）/ `failed`（失败）
  - `processing`：`images` 为空数组，请稍后轮询（建议每 2–3 秒查询一次，直到非 processing）
  - `success`：`images` 为该任务生成的图片**路径列表**（每张对应请求的 `n`，服务端按序保存；若部分下载失败可能少于 `n` 张）
  - `failed`：`error` 为失败原因，**积分已自动退回**
- `created_at`：任务提交时间（RFC 3339 格式，本地时区）
- `task_id` 不存在，或不属于该 Key 的账户：返回 `404 {"ok":false,"error":"task not found"}`

### 图片访问

`images` 返回的是站内路径，拼接站点地址即可直接访问或下载（无需 Key）：

```
http://127.0.0.1:8900/images/xxx.png
```

## 5. curl 完整示例

```bash
BASE=http://127.0.0.1:8900
KEY=sk-xxxxxxxx

# 1. 提交生成任务
curl -X POST "$BASE/api/v1/generate" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"prompt":"一只猫","n":1,"aspect_ratio":"1:1","resolution":"2k"}'

# 2. 查询任务状态（循环轮询示例）
for i in $(seq 1 30); do
  RESP=$(curl -s "$BASE/api/v1/status?task_id=123" -H "Authorization: Bearer $KEY")
  echo "$RESP"
  echo "$RESP" | grep -q '"processing"' || break
  sleep 2
done

# 3. 从响应中提取第一张图片并下载（需要 jq）
IMG=$(curl -s "$BASE/api/v1/status?task_id=123" -H "Authorization: Bearer $KEY" | jq -r '.images[0]')
curl -o cat.png "$BASE$IMG"
```

Python 示例：

```python
import time
import urllib.request
import json

BASE = "http://127.0.0.1:8900"
KEY = "sk-xxxxxxxx"

def api(path, data=None):
    req = urllib.request.Request(BASE + path, method="POST" if data else "GET")
    req.add_header("Authorization", "Bearer " + KEY)
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode("utf-8")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8"))

# 1. 提交任务
r = api("/api/v1/generate", {"prompt": "一只猫", "n": 1, "resolution": "2k"})
print(r)
task_id = r["task_id"]

# 2. 轮询直到完成
while True:
    st = api(f"/api/v1/status?task_id={task_id}")
    if st["status"] != "processing":
        break
    time.sleep(2)

# 3. 输出结果
print(st)
```

## 6. 错误码

| HTTP | 错误内容示例 | 说明 |
|------|-------------|------|
| 400 | `{"ok":false,"error":"invalid json"}` | 请求体不是合法 JSON，或字段类型错误（如 `channel` 传了数字） |
| 400 | `{"ok":false,"error":"prompt required"}` | prompt 为空 |
| 400 | `{"ok":false,"error":"prompt too long"}` | prompt 超过 4000 字 |
| 400 | `{"ok":false,"error":"所选渠道不支持 2k 分辨率，支持：1k, 4k"}` | 渠道不存在 / 分辨率不属于该渠道 |
| 401 | `{"ok":false,"error":"missing api key"}` | 缺少 Authorization / X-API-Key |
| 401 | `{"ok":false,"error":"invalid api key"}` | Key 无效或被禁用 |
| 402 | `{"ok":false,"error":"积分不足，需要 20 积分"}` | 余额不足以支付 `n × 单张费用`（此次不扣分） |
| 404 | `{"ok":false,"error":"task not found"}` | task_id 不存在或不属于该 Key 的账户 |
| 405 | `{"ok":false,"error":"method not allowed"}` | 使用了错误的 HTTP 方法 |
| 500 | `{"ok":false,"error":"系统繁忙"}` | 系统繁忙 / 任务创建失败（此情况积分已退回） |

## 7. 积分与配额说明

- 单张生成费用 = 系统设置「消耗积分 / 次」，多张按数量倍乘。
- 提交任务时**立即条件扣减**；生成失败时**自动全额退回**（无需申请）。
- 生成任务**无数量上限**（无并发配额），但图片会占用服务器磁盘，请合理使用。
- API 与网页共用同一积分账户，网页消耗会同步影响 API 余额。

## 8. 常见问题

**Q：为什么提交返回 `400 invalid json`？**
检查请求体是否合法 JSON，且所有字段类型正确——尤其是 `channel` 必须传字符串 `"0"` 而不是数字 `0`。

**Q：返回的图片是 URL 还是 Base64？**
返回格式由系统后台自适应固定，状态接口的 `images` 返回站内图片路径（如 `/images/xxx.png`），拼接站点地址即可下载。不支持也不需要用 `response_format` 参数。

**Q：生成失败了积分会退回吗？**
会。任务失败时积分自动全额退回，错误信息见状态接口的 `error` 字段。

**Q：如何查看我已经用掉的积分？**
API 消耗会记录在个人主页 →「积分明细」中。

## 9. 图片存储与自动清理

- 生成的图片默认保存在**服务器本地**（`data/images/`），状态接口的 `images` 返回站内路径。
- 管理员可在后台配置**外部长期存储**（S3 兼容对象存储 / WebDAV / POST 上传接口）：图片下载落盘后会自动上传一份到外部存储，并记录每张图的存储方式与远端路径。服务器本地文件即使被清理，用户仍可在创作记录页通过「备用下载」按钮获取图片。
- 管理员可启用**自动清理**（后台设置）：
  - **按保留天数**：超过设定天数的旧记录被清理；
  - **按磁盘上限**：本地图片目录超过设定大小时按旧到新删除。
  - 已上传外部存储的图片清理时仅删除本地文件，保留记录与备用下载地址。
- 创作记录页的图片默认**缓存到浏览器本地**（IndexedDB），服务器清理后浏览器仍可查看/下载已缓存图片。
