# EasyConnect 密码策略兼容

来源：本机 EasyConnect 7.6.7.10 的 Web SDK，以及同一网关公开提供的改密页面。仅据协议行为实现兼容，未打包官方 JavaScript。未对真实账号执行改密。

## 登录后的策略检查

官方 SDK `common/dto.js` 从登录响应读取 `pwpErrorCode`、`pwdRemaintm`。本机 `local/connect/connect.js` 在认证成功之后进入 `views/password_change` 流程，因此 `ErrorCode=1` 本身不代表可以立即建隧道。

- `pwpErrorCode=4`：提前到期提醒，可以继续连接。
- 包含位 `2`：密码已过期。
- 包含位 `16`：首次登录必须更改初始密码。
- 其他非零策略结果：进入改密流程，由网关最终判定。

收到强制策略时不建立隧道，CLI 提示使用 `change-password`，GUI 显示修改入口。不会自动选择密码或循环重试认证。结构化策略只包含数值字段，不包含会话 Cookie、CSRF 或密码。

## 修改密码

官方 `api/person_setting.js` / `business/user_settings.js`：

1. 使用当前密码建立普通 HTTPS 认证会话。
2. GET `/por/perinfo.csp`，读取 `ALL_ENABLE_PWP`、`MINLEN`、`CSRF_RAND_CODE`。
3. POST `/por/changepwd.csp?cknote=0`，表单字段为 `pripsw`、`newpsw`、`svpn_req_randcode`。
4. 强制改密页面在已认证会话中省略旧密码值；普通主动改密提交旧密码。
5. 除 `ErrorCode=1` 外，还必须检查 `PswMask`；非零表示密码未满足策略，不能更新本地凭据。
6. 确认成功后更新系统凭据存储，结束改密会话，由用户重新连接。退出会话失败不能把已经成功的改密报告为失败。

策略校验位：`1` 最小长度、`8` 不含用户名、`32` 启用复杂度、`64` 数字、`128` 字母、`256` 特殊字符 `!@#$%^&*()`、`512` 不同于旧密码。服务端仍是最终判定者。

公开 `/public/psw_policy` 在 2026-10-12 返回有效期 90 天、提醒期 15 天、要求修改初始密码；这是网关配置，不代表某一账号的剩余有效期。

## 验证范围

合成响应测试覆盖：认证成功但必须改密、仅提醒、策略位校验、失败认证不得提交、POST 字段和 CSRF、成功状态附带拒绝掩码。实际账号改密由用户在 CLI/GUI 主动触发后验证。
