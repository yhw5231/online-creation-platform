# 在线创作平台 - API 接口文档

通过 API Key 调用生成图片接口（OpenAI 兼容），积分扣减规则与网页完全相同。本平台默认监听 `:8900`（可用环境变量 `PORT` 覆盖）。

## 目录

1. [获取 API Key](#1-获取-api-key)
2. [认证方式](#2-认证方式)
3. [生成图片（OpenAI 兼容）](#3-生成图片openai-兼容)
4. [查询可用渠道](#4-查询可用渠道)
5. [查询任务状态（旧接口）](#5-查询任务状态旧接口)
6. [curl 完整示例](#6-curl-完整示例)
7. [错误码](#7-错误码)
8. [积分与配额说明](#8-积分与配额说明)
9. [常见问题](#9-常见问题)

## 1. 获取 API Key

登录平台进入 **个人主页（/profile）** →「API Key」卡片：

- 可生成**多个** API Key，每个 Key 需填写**名称**（如「官网小程序」「脚本A」）用于区分用途。
- 每个 Key 在生成时**必须绑定一个生成渠道**：`/v1/images/generations` 的 OpenAI 格式请求中不含渠道参数，因此「用哪个渠道」在创建 Key 时就固定下来，无法在调用时更改。
- 新 Key 明文**仅显示一次**，请立即复制保存；数据库只保存 Key 的 SHA-256 哈希，无法找回明文。
- 随时可**删除**任意 Key（删除后该 Key 立即失效），也可继续生成更多 Key。

## 2. 认证方式

所有受保护接口在请求头携带任意一个有效 Key，二选一：

```
Authorization: Bearer sk-xxxxxxxx
```

或：

```
X-API-Key: sk-xxxxxxxx
```

- Key 缺失：返回 `401`。
- Key 无效 / 已删除 / 对应用户已被禁用：返回 `401`（旧版单 Key 接口返回 `{"ok":false,"error":"invalid api key"}`）。

## 3. 生成图片（OpenAI 兼容）

### 请求

`POST /v1/images/generations`

请求头：

```
Authorization: Bearer sk-xxxxxxxx
Content-Type: application/json
```

请求体（JSON，与 OpenAI Images API 格式一致）：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `prompt` | string | 是 | 提示词，最长 4000 字（UTF-8 按字符数计） |
| `model` | string | 否 | 生成模型，须为该 Key 绑定渠道支持的模型；留空自动用渠道默认模型 |
| `n` | int | 否 | 生成数量，1–4，默认 1；超出范围自动收敛到 1–4 |
| `size` | string | 否 | OpenAI 尺寸，如 `1024x1024` / `1792x1024` / `1024x1792`，自动换算为宽高比与分辨率档位；默认 `1024x1024` |
| `response_format` | string | 否 | `url`（默认，返回图片地址）或 `b64_json`（返回图片 base64 内容） |

> 「渠道」等本站专有参数随 API Key 绑定，请求体中**无需也不能**指定（旧版 `/api/v1/generate` 的 `channel` / `aspect_ratio` / `resolution` 参数在 OpenAI 格式中不再使用）。

示例：

```json
{"prompt": "一只猫，在窗台晒太阳", "n": 2, "size": "1024x1024"}
```

### 响应（成功）

```json
{
  "created": 1750000000,
  "data": [
    {"url": "/images/1750000000000_ab12cd.png"},
    {"url": "/images/1750000000000_ef3456.png"}
  ]
}
```

请求 `response_format=b64_json` 时 `data` 每项为：

```json
{"b64_json": "iVBORw0KGgoAA..."}
```

- 本接口为**同步返回**：会等待图片生成完成后一次性返回结果（OpenAI 语义）。
- 积分在提交时按 `n × 单张费用` **条件扣减**（余额不足不扣减并返回 402）。
- 单张费用等于系统设置中的「消耗积分 / 次」（网页与 API 一致）。
- 图片地址拼接站点地址即可访问/下载（无需 Key）：`http://127.0.0.1:8900/images/xxx.png`。

## 4. 查询可用渠道

`GET /api/v1/channels`（需要 API Key）：返回当前配置的全部生成渠道与各自的稳定编号，创建 API Key 前可先查询确认要绑定的渠道。

```json
{
  "ok": true,
  "channels": [
    {
      "id": 1,
      "index": 0,
      "name": "主渠道",
      "nsfw": false,
      "model": "grok-imagine-image-lite",
      "resolutions": ["1k", "2k"],
      "models": ["grok-imagine-image-lite", "grok-imagine-image"]
    },
    {
      "id": 3,
      "index": 1,
      "name": "NSFW 渠道",
      "nsfw": true,
      "model": "grok-imagine-video",
      "resolutions": ["1k", "2k", "4k"],
      "models": ["grok-imagine-video"]
    }
  ],
  "hint": "渠道编号（id 字段）在渠道创建时分配，不随增删/排序变化"
}
```

- `id`：渠道**稳定编号**，即个人主页「生成 API Key」时绑定渠道下拉的取值。
- `index`：仅为当前列表的**展示顺序**，会随渠道增删变化，**不要**用作渠道标识。
- `resolutions` / `models`：该渠道支持的档位与模型，便于创建 Key 前确认（如 NSFW 渠道只支持 `1k`，绑定后请求 `size=1792x1024`（2k）会返回 400）。

## 5. 查询任务状态（旧接口）

`GET /api/v1/status?task_id=123`（需要 API Key）—— 仅用于兼容旧版调用方，新代码调用 OpenAI 兼容接口即可，无需轮询。

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
  - `success`：`images` 为该任务生成的图片**路径列表**
  - `failed`：`error` 为失败原因，**积分已自动退回**
- `task_id` 不存在，或不属于该 Key 的账户：返回 `404 {"ok":false,"error":"task not found"}`

## 6. curl 完整示例

```bash
BASE=http://127.0.0.1:8900
KEY=sk-xxxxxxxx

# 0. 查询可用渠道（确认要绑定的渠道编号）
curl -s "$BASE/api/v1/channels" -H "Authorization: Bearer $KEY"

# 1. 生成图片（OpenAI 兼容，同步返回）
curl -X POST "$BASE/v1/images/generations" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"prompt":"一只猫","n":1,"size":"1024x1024"}'

# 2. 生成 2 张并返回 base64
curl -X POST "$BASE/v1/images/generations" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"prompt":"一只猫","n":2,"response_format":"b64_json"}'

# 3. 从响应中提取第一张图片并下载（需要 jq）
IMG=$(curl -s -X POST "$BASE/v1/images/generations" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d '{"prompt":"一只猫"}' | jq -r '.data[0].url')
curl -o cat.png "$BASE$IMG"
```

Python 示例（OpenAI SDK 兼容写法）：

```python
import json
import urllib.request

BASE = "http://127.0.0.1:8900"
KEY = "sk-xxxxxxxx"

def generate(prompt, n=1, size="1024x1024", response_format="url"):
    req = urllib.request.Request(
        BASE + "/v1/images/generations",
        method="POST",
        data=json.dumps({
            "prompt": prompt, "n": n,
            "size": size, "response_format": response_format,
        }).encode("utf-8"),
    )
    req.add_header("Authorization", "Bearer " + KEY)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8"))

# 同步返回结果，images 已就绪
r = generate("一只猫", n=1)
print(r)
# {'created': 1750000000, 'data': [{'url': '/images/xxx.png'}]}
```

## 7. 错误码

| HTTP | 说明 |
|------|------|
| 400 | 参数错误：无效 JSON / prompt 为空或超长 / size 或模型不被渠道支持 / response_format 非法，`error.message` 为具体原因 |
| 401 | API Key 缺失或无效 |
| 402 | 积分不足（`error.message` 含所需积分，此次不扣分） |
| 404 | 查询状态时任务不存在（旧接口） |
| 405 | 使用了错误的 HTTP 方法 |
| 500 | 系统繁忙 / 任务创建失败（此情况积分已退回） / 生成失败（`error.message` 为原因，积分已退回） |

## 8. 积分与配额说明

- 单张生成费用 = 系统设置「消耗积分 / 次」，多张按数量倍乘。
- 提交任务时**立即条件扣减**；生成失败（`500`）时**自动全额退回**（无需申请）。
- 生成任务**无数量上限**（无并发配额），但图片会占用服务器磁盘，请合理使用。
- API 与网页共用同一积分账户，网页消耗会同步影响 API 余额。

## 9. 常见问题

**Q：为什么调用返回 `400 无效的 API Key` / 401？**
检查请求头 Key 是否正确、是否已删除，以及账号是否被禁用。注意每个 Key 独立管理，删除后立即失效。

**Q：怎么指定用哪个渠道？**
在个人主页生成 API Key 时选择绑定的渠道。OpenAI 格式请求中不带渠道参数，因此渠道固定在 Key 上；如需换渠道，请另建一个绑定该渠道的新 Key。

**Q：`size` 怎么映射到分辨率？**
按最长边映射：≤1024 → `1k`、≤2048 → `2k`、更大 → `4k`，同时按宽高比就近匹配 `1:1 / 16:9 / 4:3 / 3:4 / 9:16 / 21:9`。若绑定的渠道不支持该档位（如 NSFW 渠道仅支持 `1k`），返回 400 并列出支持的档位。

**Q：返回的图片是 URL 还是 Base64？**
默认 `url`（站内路径，拼接站点地址即可下载）；请求 `response_format=b64_json` 时返回图片的 base64 内容。

**Q：生成失败了积分会退回吗？**
会。任务失败时积分自动全额退回，错误信息见响应 `error.message`。

**Q：如何查看我已经用掉的积分？**
API 消耗会记录在个人主页 →「积分明细」中。

## 10. 图片存储与自动清理

- 生成的图片默认保存在**服务器本地**（`data/images/`），接口返回站内路径。
- 管理员可在后台配置**外部长期存储**（S3 兼容对象存储 / WebDAV / POST 上传接口）：图片下载落盘后会自动上传一份到外部存储，并记录每张图的存储方式与远端路径。服务器本地文件即使被清理，用户仍可在创作记录页通过「备用下载」按钮获取图片。
- 管理员可启用**自动清理**（后台设置）：
  - **按保留天数**：超过设定天数的旧记录被清理；
  - **按磁盘上限**：本地图片目录超过设定大小时按旧到新删除。
  - 已上传外部存储的图片清理时仅删除本地文件，保留记录与备用下载地址。
- 创作记录页的图片默认**缓存到浏览器本地**（IndexedDB），服务器清理后浏览器仍可查看/下载已缓存图片。