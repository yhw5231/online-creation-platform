# Grok 图片生成 API 开发文档

## 基本信息
- **Base URL**: https://grok.7890456.xyz/v1
- **鉴权**: Authorization: Bearer g2a_...
- **端点**: POST /v1/images/generations

## 请求参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| model | string | 是 | 已启用且可用账号支持的模型名称 |
| prompt | string | 是 | 图片生成的提示词 |
| 
 | integer | 否 | 返回图片数量，网关自动匹配上游批次 |
| aspect_ratio | string | 否 | 宽高比，支持 1:1、16:9、9:16、4:3、3:4、3:2、2:3 |
| esolution | string | 否 | 分辨率，图片支持 1k / 2k |
| esponse_format | string | 否 | url 或 64_json，默认 url |
| stream | boolean | 否 | 是否启用 SSE 流式输出，默认 alse |

## 请求示例

`ash
curl -X POST "https://grok.7890456.xyz/v1/images/generations" \
  -H "Authorization: Bearer g2a_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "grok-imagine-image-lite",
    "prompt": "A minimal red chair in a bright studio",
    "n": 1,
    "response_format": "url"
  }'
`

`javascript
const response = await fetch("https://grok.7890456.xyz/v1/images/generations", {
  method: "POST",
  headers: {
    "Authorization": "Bearer g2a_your_api_key",
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    "model": "grok-imagine-image-lite",
    "prompt": "A minimal red chair in a bright studio",
    "n": 1,
    "response_format": "url"
  })
});
const data = await response.json();
`

## 响应格式

`json
{
  "created": 1783860000,
  "data": [
    {
      "url": "http://127.0.0.1:8000/v1/media/images/example"
    }
  ]
}
`

若 esponse_format 为 64_json，则 data[].b64_json 返回 Base64 编码的图片内容。

## 实现说明
- 网关可能以 4、8、12 张的批次向上游请求，仅返回 
 张结果。
- 生成结果统一归档媒体存储；url 返回网关资源地址，64_json 返回编码内容。
