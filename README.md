# dsh-connect-qoder-pro

将本机已登录的 **Qoder 桌面 App（国内版）** 模型接入 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)，零配置、只读登录态、不启动任何独立授权流程。

## 工作原理

```
DSH 模型选择器
  → pi-ai provider (qoder-cn)
  → 本机 loopback shim（随机端口 + 进程内随机 secret，OpenAI 兼容 /v1）
  → Qoder CN 网关（COSY 签名 + Encode=1 置换编码 + 双层 SSE 信封）
  → OpenAI 风格 chunk 流回 DSH
```

- **凭据**：直接读取 `%APPDATA%\com.qodercn.app.stable\auth.v1.dat`（Chromium OSCrypt `v10` AES-256-GCM 信封；主密钥从 App `Local State` 经 DPAPI 解出）。只读，不写不改。
- **协议**：每请求随机 AES-128-CBC 密钥包用户信息，RSA 包密钥，MD5 签名（`Authorization: Bearer COSY.<payload>.<sig>` + `Cosy-*` 头）；请求体 base64 → 置换字母表 → 三分之一旋转；SSE 每帧是信封对象，其 `body` 字段才是 OpenAI chunk。
- **模型目录**：启动与每 30s 轮询 `GET algo/api/v2/model/list?Encode=1`，取 `chat` 分组的 14 个模型（Qwen3.8/DeepSeek-V4/GLM-5.3/Kimi-K3/MiniMax-M2.7 等）。
- **错误映射**：今日次数用完(110)→402、排队(10605)→429、登录失效(105)→401、其余→502/400。上游错误藏在 200 帧里，逐帧判别。

## 账号能力（每日签到 / 用量 / 账户状态）

OpenAPI 主机（`openapi.qoder.com.cn`）走**明文 bearer**，不需要 COSY 签名与体编码。shim 同端口下暴露四条同源自检路由（由 DSH web server 同源代理，浏览器可直接访问）：

| 路由 | 方法 | 说明 |
|---|---|---|
| `/plugins/dsh-connect-qoder-pro/status` | GET | 激活状态、区域、注册结果（错误只发 `errorName`，不泄露路径） |
| `/plugins/dsh-connect-qoder-pro/usage` | GET | 用量（presentation 优先，quota 回退）+ 今日签到状态；`?refresh=1` 强刷，20s TTL + 单飞 |
| `/plugins/dsh-connect-qoder-pro/checkin` | POST | 每日签到（CLAIM_BENEFIT，上游幂等，已领回 `alreadyClaimed`） |
| `/plugins/dsh-connect-qoder-pro/account` | GET | 本地登录态（uid/昵称/过期时间），无网络 |

实现口径均按实测固化：只认 `actionType==="CLAIM_BENEFIT"`（同账号的 `VIEW_DETAILS` 行也报 `CLAIMED`，不能只看 status）；未知 `claimStatus` 当可领（上游幂等，悲观成本是功能永久隐藏）；领取成功后作废用量缓存再回读，否则 20s TTL 会 join 旧 fetch 拿到旧余额。

## 模型口径细节

- `compat.supportsDeveloperRole:false` 必须显式：pi-ai 对 loopback baseUrl 自动探测为 true，reasoning 模型会发 `role:"developer"`，Qoder 恒 403/10605。
- `maxTokens` 钉 65536（PROBED）：不声明会落 32768 默认，reasoning 与回答共享预算被腰斩。
- `price_factor` 是**折后价**，白天仅读它会低估 2.5–5 倍；`before_promotion_price_factor` 才是窗外价。错峰窗口 22:00–08:00（Asia/Shanghai，4 折）按 `promotion.active===true && 窗口开` 判定——上游 `active` 是瞬时折扣态，窗外取到的 `false` 无信息量，只有窗口开着却报 `false` 才是活动被 kill。

## 安装

在 DeepSeek Harness 侧边栏的 **插件** 界面中，点击 **添加插件**，输入包名或仓库地址：

```bash
github:wshdp123/dsh-connect-qoder-pro
```

或者通过 DSH CLI 安装：

```bash
dsh plugin --profile desktop add github:wshdp123/dsh-connect-qoder-pro
```

> **系统要求**：
> 1. 本机已安装并登录 **Qoder 桌面 App（国内版）**。
> 2. 当前仅支持 Windows 系统（凭据动态读取依赖 Windows DPAPI）。
