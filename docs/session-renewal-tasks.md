# 会话续期实现与验证记录

更新日期：2026-10-13。工作目录：`/Users/class-undefined/code/vibe-coding/easy-connect`。
调查起点为 `main` / `cbb8f95` / `0.4.13`；实现版本为 `0.4.14`，Rust 工具链 `1.94.1`。

## 目标与当前状态

目标是修复 EasyConnect Rust 连接约五分钟后自动断开的问题，并在用户实际网关验证持续连接。用户已要求参考官方 EasyConnect.app，使用 REA 分析对照。

**0.4.14 已实现并默认接入正式连接的 TIMQ/ACKQ 续期生命周期，并通过本机网关 15 分钟空闲连接及随后的内网 TCP 访问验证。** 用户在完成 P0 实验后明确要求“续期需要实现”；本次实现沿用已说明的旧式明文、无服务器认证的续期协议，数据通道继续使用现有 TLS。

- 认证成功并建立数据面后启动独立工作线程；初始请求类型 4，周期请求类型 3，约每 5 秒一次，不重复提交账号密码。
- 正数有效期更新截止时间；类型 2 只确认响应，不延长有效期。初始期限 300 秒来自官方客户端；60 秒无有效响应上限、3 秒单次 I/O 和重试等待、64 KiB 广播上限是本地策略。
- I/O 错误关闭整条续期连接，再用原会话重新握手；半帧不在原 socket 上继续解析。恢复受会话有效期与 60 秒响应预算共同约束。
- 服务器超时、非法有效期、未知消息或预算耗尽终止整个数据面。门户仍用于确认明确注销原因；在线或查询失败不能覆盖已结束的续期状态。
- CLI/TUN/SOCKS/GUI 后台共用生命周期。主动断开唤醒等待、关闭已登记的新旧 socket，并等待线程回收；保留现有 DNS/路由清理与 Linux 明确结束时的退出码 77。
- **会话 ID 替换目前整体断开并提示手动重连。** 不采用新 ID，不以旧地址/配置继续运行，不自动重新登录，也不对替换会话发注销请求。透明协调 token、资源配置、虚拟地址和所有通道的会话替换仍未实现。

实网：原先 20 秒 P0 实验成功；首次生产 SOCKS 测试收到正数有效期后，在续期启动约 40,135 ms 收到归类为 `ServerTimeout` 的终止应答，自动清理退出，未达到 15 分钟。该版本将 type 3 和非法有效期归入同一终止原因，不能由这条日志区分二者；随后已补充安全的终止应答分类及确认次数日志。用户授权检查 `root@hk` 后，确认 `easy-connect.service` 仍 active/running（PID 660582），日志存在反复断线重连；已正常停止，确认 MainPID=0、inactive/dead 且无残留 VPN 进程。该发现说明存在会话冲突条件，但不能单凭它确定第一次结束的原因。随后改用已签名 0.4.14 Release 开始重新验证。

生产实网验收（停止 `hk` 后）：2026-10-13 11:19～11:34（Asia/Shanghai），从隧道就绪计时空闲连接 **900,120 ms**，末次采样在 898,104 ms，累计 **180 次**正数续期确认；随后经 SOCKS 成功建立内网 TCP 22 连接。自动 SIGINT 退出，最终用时 900,328 ms、进程退出码 0，日志没有续期失败或通道恢复记录。日志保存在被忽略的 `analysis/connection-rea/production-renewal-20261013-111900.log`。这证明本次网关、该会话与当前构建下越过三个五分钟窗口；不能单独排除旧问题中的同账号冲突因素，也不代表其他网关或更长时段均已验证。

自动化验证：`ec-compat` 库 126 项测试全部通过；桌面应用库 81 项通过、1 项原有测试跳过。协议库（含测试）、桌面 bins 与 examples 的 Clippy `-D warnings` 通过，限定文件 rustfmt 和 `git diff --check` 通过。新增集成测试确认服务器结束续期会关闭全部数据通道并通知监控器，手动断开会回收握手中的续期线程。

实现文件：`session_renewal.rs` 负责线协议，`session_renewal/maintenance.rs` 负责期限/恢复/取消，`engine/data_plane.rs` 负责传输关闭与线程回收，`engine/session.rs` 负责认证后启动和终止状态协调，`session_status.rs` 增加会话替换的用户提示。`session-renewal-login` 示例也改为调用正式生命周期，避免额外建立第二条续期连接。

构建与安装：已构建并签名 macOS arm64 的匹配 CLI/GUI，产物为 `dist/easy-connect-0.4.14-macos-aarch64.dmg`。应用已安装到 `/Applications/EasyConnect Rust.app`；用户完成系统管理员授权后，后台 RPC 返回 0.4.14 / disconnected，且 `/Library/PrivilegedHelperTools/easy-connect` 与应用内 CLI 的 SHA-256 一致。原 0.4.13 应用保存在 `.release-stage/installed-0.4.13-before-renewal.app`。已启动安装后的 GUI 并通过后台建立 TUN（utun9、55 条路由），出现正式续期确认；路由查询确认内网目标走 utun9，ICMP 3/3 成功、0% 丢包，TCP 22 连接成功。随后主动断开：后台回到 disconnected、routes=0、interface=null，utun9 消失，内网目标不再指向 VPN 接口。最后重新启动 GUI，恢复正常桌面使用。

## 历史证据：P0 传输验证与真实会话结果

2026-10-13 在目标网关执行了无凭据实验，均使用 16 个 ASCII `0` 的占位 ID，没有读取现有进程的会话材料，也没有运行官方程序副本：

| 实验 | 实际结果 | 能证明什么 |
| --- | --- | --- |
| 官方旧式 82/122/43 字节握手 + TIMQ type 4 | 首次 80 ms，收到完整 60 字节 ACKQ type 3，正文长度 0；Rust 诊断复核 23 ms，同样 TimedOut | 网关识别旧式续期报文并拒绝占位 ID；不证明有效会话续期 |
| 独立 TCPP TLS 1.1 + TIMQ type 4 | 证书和 Finished 验证通过；应用读取在约 3 秒后超时 | 不能把 TLS 握手成功当作支持 TLS 内 TIMQ |
| 独立 TCPP TLS 1.1 + 官方库 C01/C02 文本握手 | C01 返回 33 字节，C02 返回 13 字节，前缀匹配 | 识别资源代理文本协议；未证明认证成功或续期 |

**新的明确边界：官方旧式续期没有服务器身份校验，也没有加密。** CSClient 的 122 字节应答只检查长度；底层 libCMS 直接调用 TCP `read`/`write`。TWFID 出现在首包偏移 44 的 16 字节和后续 TIMQ 中。先验证另一条 HTTPS 连接的证书，不能保护这条独立裸 TCP 连接。

已准备可审查的诊断程序：

- `examples/session-renewal-transport.rs`：固定占位 ID，支持 `legacy-dummy`、`tls-timq`、`tls-text`，无真实登录入口。
- `examples/session-renewal-login.rs`：正常 HTTPS 登录后，同时建立现有 TLS 数据面和独立旧式续期，默认实验 20 秒。要求显式 `--allow-plaintext-session-id`；账号密码由本机终端隐藏输入。只记录回复分类、正文长度、正数有效期和耗时，不安装 TUN、DNS 或路由。
- `vendor/ec-compat/src/session_renewal.rs`：类型 4 初始请求、类型 3 周期请求、60 字节头、64 KiB 正文上限、完整读取、总读取期限、EOF/错误后关闭，以及会话切换分类。P0 时仅用于诊断；现已增加生产维护线程，切换处理边界见上文。

用户已在知悉**明文会话 ID/无服务器认证**风险后回复 “do it”，明确授权一次 20 秒真实会话实验；凭据由用户在本机终端隐藏输入。该次授权仅针对诊断；用户随后另行明确要求实现续期，生产状态见本文开头。此前确认来自本任务 P0 的身份校验要求和实际协议证据，不是工具审批拒绝，也不是 REA 技能强制审批。

**真实会话实验已成功完成。** 2026-10-13 10:54:40～10:55:13（Asia/Shanghai，包含人工输入、登录和退出），数据面建立后的协议观察窗口精确为 20,000 ms：

| 建立数据面后经过时间 | 续期通道应答 | 有效期字段 | 追加正文 |
| --- | --- | --- | --- |
| 86 ms | ACKQ type 5 / Connected | 不更新期限 | 0 字节 |
| 5,102 ms | ACKQ type 1 / Renewed | 2,591,995 秒 | 0 字节 |
| 10,111 ms | ACKQ type 1 / Renewed | 2,591,990 秒 | 0 字节 |
| 15,122 ms | ACKQ type 1 / Renewed | 2,591,985 秒 | 0 字节 |

20,000 ms 时程序报告 `positive_renewals=3`、`data_transport_open=true`、`internal_access_tested=false`；退出码 0，注销请求未报错，诊断进程已退出。日志在被 git 忽略的 `analysis/connection-rea/renewal-login-20s.log`，不含密码、TWFID、token 或原始响应。

该结果确认**正常认证的旧式续期通道可与当前 TLS 数据面共存至少 20 秒**，并收到真实正数有效期；不证明 15 分钟持续连接或内网访问，也不证明重连、切换和正式安装后的行为。约 30 天的字段值逐次减少 5 秒，推测是会话剩余总有效期，而不是每个应答都把总截止时间向后延长。不能将它写成已测得网关的空闲超时，也不能把官方本地初始 300 秒冒充网关下发值。

```sh
cargo build --locked --examples
# 无凭据；将网关和证书指纹替换为已有受信任配置
./target/debug/examples/session-renewal-transport https://vpn.example.com CERT_SHA256 legacy-dummy
# 仅在明确接受上述风险、退出其他同账号客户端后，由用户本机输入凭据
./target/debug/examples/session-renewal-login --gateway https://vpn.example.com --cert-sha256 CERT_SHA256 --allow-plaintext-session-id --seconds 20
```

已通过：`ec-compat` 全部 115 项库测试（本次新增 8 项续期测试、1 项 TLS 通道标记测试）、应用库 48 项测试、库与 examples 的 Clippy（`-D warnings`）、限定修改文件的 rustfmt、`git diff --check`、两个诊断程序构建，以及上述 20 秒真实正数续期实验。未提供风险接受参数时，真实登录诊断在提示凭据/联网前退出，已核实。15 分钟连接、内网访问、安装后的验证均未完成。诊断程序即使报告 `data_transport_open=true`，也明确保留 `internal_access_tested=false`，不能据此验收 VPN 连通性。

调查初期用户反馈：通常约五分钟断开，Tailscale subnet 已关闭。当时尚未检查 Linux VPN；后续已在 `hk` 确认并停止仍在运行的 VPN 服务，见本文开头。关闭子网发布与停止 VPN 登录进程是两件事。

## 已取得的运行证据

此前通过本机后台服务的只读 Status RPC 取得以下信息，与用户粘贴的日志一致：

- 后台版本 `0.4.13`，状态 `failed`，结束原因 `connection_lost`。
- 资源加载和 TUN 建立成功，55 条路由，出现 `VPN command heartbeat confirmed`。
- 控制通道报 `VPN transport closed`，接收通道报 `failed to fill whole buffer`。
- 门户状态查询失败；控制与接收通道恢复均报 `unexpected status`。
- 控制通道恢复三次失败，随后整个数据面停止。

这证明了断线与恢复失败的顺序，不能据此断言被顶号、管理员踢出或心跳回复超时。原日志没有时间戳、实际回复状态码和门户查询失败细节，无法还原网关的确切注销原因。

服务事件日志目前只存在后台服务内存中，保留最近 100 行/64 KiB；重新连接会重置会话状态，服务重启也会丢失历史。实测前应先保存当次诊断，日志中不要保存密码、TWFID、token 或响应原文。

## 官方实现已经确认的事实

详细证据见 [connection-maintenance.md](connection-maintenance.md) 和本地 [native-findings.md](../analysis/connection-rea/native-findings.md)。

1. 真正的网关会话保活位于 `CSClient.app` 的 `TimeQry`，不是 ECAgent 的 `CSTimeQuery`。后者的 HEARTBEAT 是本地 IPC。
2. `TimeQry` 是公共会话服务，收到有效 `__SVPN__` 配置后启动；不以存在 TCP 代理资源为条件，正常 L3VPN-only 会话也会启动。
3. `TimeQry::Run` 把本地初始有效截止时间设为当前启动后秒数加 **300 秒**。这是客户端本地常量，尚未证明本次网关实际下发的期限就是 300 秒。
4. 独立连接先执行 82 字节旧式握手，读取 122 字节应答，再发送 43 字节固定确认和类型 4 的 TIMQ。
5. 本机 macOS 官方样本的周期 TIMQ 类型为 **3**；成功收发后最多等待五次 `Wait(1)`，约五秒一轮，可被事件提前唤醒。不要直接复制 Linux 参考实现的类型 1。
6. TIMQ 长度 28 字节：magic、BE32 类型、BE32 启动后秒数、16 字节 TWFID。
7. ACKQ 先读取 60 字节头，偏移 56 的 BE32 表示追加广播正文长度。类型 1 用偏移 12 的正数秒值延长有效期；类型 2 仅确认；类型 3 超时并查注销原因；类型 4 切换会话；类型 5 确认连接。
8. 官方支持新会话替换：校验新 ID、处理旧会话、保存新 TWFID、更新配置。Rust 目前复用旧 token 恢复数据通道，没有对应更新链。
9. 前端默认查本地 ECAgent，只有无 agent 或显式 byServer 时才访问 `timequery.csp`。**不能把缺少定时门户查询直接等同于根因，也不能未经验证用周期 HTTP 查询替代协议续期。**

调查时判断：0.4.13 缺少上述会话续期，而 L3 命令/数据心跳不能证明登录会话续期。0.4.14 已补齐维护线程；具体实网验证与剩余限制见本文开头。

## 待办任务（按依赖顺序）

### P0：确定目标网关可用的续期传输

- [x] 阅读现有调查证据及 `engine/session.rs`、`engine/data_plane.rs`、`modern.rs`、`special_tls11.rs`、`session_status.rs`、`src/cli.rs`。
- [x] 对照官方握手字节及 TimeQry 状态机，确定独立续期连接如何接入目标网关；已在真实登录中确认与当前 TLS 数据面共存 20 秒，长期验证仍属于 P2。
- [x] 明确旧式握手与当前 TLS 的边界、服务器身份校验和会话材料的处理；已确认旧式续期是未认证裸 TCP，真实会话实验需明确接受风险。独立 TCPP 实验未改变 L3 通道。
- [x] 在正常授权登录流程中做最小验证，得到有效 TIMQ/ACKQ 应答及续期秒数；完成 20 秒窗口、3 次正数有效期应答，记录脱敏分类、长度和耗时；未运行官方程序副本。
- [x] 目标网关已接受旧式握手并返回真实正数有效期；长期会话结束原因仍需按 P2 验证，不扩大重试次数掩盖问题。

### P1：实现会话续期生命周期

- [x] 将会话续期实现为独立模块，与现有控制/发送/接收通道分工清楚；复用已认证会话，不重复提交账号密码。
- [x] 实现握手、消息编码、完整读取、应答分类、有效截止时间更新，以及有界的追加正文读取。
- [x] 处理分段和合并响应、未知消息、非法长度和 EOF；避免单次读超时破坏帧边界或加密状态。
- [x] 在有效期内恢复续期连接，明确恢复预算与终止条件；不要用假在线状态掩盖续期长期失败。
- [x] 区分服务器超时、明确注销、会话切换和普通网络故障；切换时终止整个旧数据面并提示重连。
- [ ] 透明会话切换：协调替换 token、资源配置、虚拟地址和所有数据通道；目前明确不支持。
- [x] 接入 CLI/TUN/SOCKS 的共同生命周期；主动断开应取消等待、关闭新旧 socket 并回收线程，保留现有 DNS/路由清理。
- [x] 确认被顶号或服务器结束会话时仍不自动登录，避免争抢会话；保留 Linux 对明确结束原因返回 77 的行为。
- [x] 增加可定位的安全日志：连接后经过时间、续期首次确认、续期失败类别、恢复结果和终止原因；不记录原始会话材料。

### P2：验证与回归

- [x] 编码/解析测试应引用本机官方证据的字段和类型，不能只让自写编码器与自写解码器互相证明。
- [x] 使用本地模拟服务器验证分段读取、广播正文边界、超时、恢复、停止取消以及服务器会话结束。
- [x] 覆盖有效期续期、零/非法有效期、新会话切换、旧会话任务不能覆盖新状态。
- [x] 运行受影响单元测试、格式检查和 Clippy；按新增模块影响范围扩展回归。
- [x] 实际网关连续空闲 900,120 ms，180 次正数续期确认，随后内网 TCP 连接成功。
- [x] 本地模拟服务器验证短暂断线恢复；真实 SOCKS 测试主动退出码 0。
- [x] 安装后的真实 TUN 主动断开清理：路由数回到 0，虚拟接口消失，后台状态 disconnected。
- [ ] 真实物理网络中断后的恢复仍未主动制造验证；未制造其他设备顶号。

### P3：构建、安装与交付

- [x] 更新必要文档，明确已验证行为、兼容范围和剩余限制。
- [x] 构建匹配版本的 CLI 与 GUI；沿用现有打包/签名流程。
- [x] 安装并运行 0.4.14 GUI 与后台；后台 RPC 版本及 helper/内置 CLI 哈希已核对。
- [x] 安装后 TUN 连接出现正式续期确认，内网 ICMP/TCP 成功，主动断开完成路由/接口清理。
- [x] 本文分别记录协议实现、自动化测试、实网连接与安装状态，以及透明切换、真实物理断网测试的剩余限制。

## 历史诊断补丁与验证（生产实现之前）

本轮修改的源码：

- `vendor/ec-compat/src/modern.rs`：非预期回复记录 expected/actual **首字节**状态和回复长度，不记录正文；接受条件未变。
- `src/cli.rs`：普通和最终会话查询失败都记录白名单内安全错误类别，未知详情脱敏；查询调度、重试和退出行为未变。
- `vendor/ec-compat/src/session_status.rs`：`externsession#oldsessid=` 响应单独返回固定的 unsupported session switch 错误，仍未实现会话切换。
- `docs/connection-maintenance.md`：新增官方原生续期证据和修复边界。

以下已通过，共 30 项相关测试；这是诊断补丁验证，不是续期实现验收：

```sh
cargo test --locked -p ec-compat --lib modern::tests        # 9
cargo test --locked -p ec-compat --lib session_status::tests # 6
cargo test --locked --lib cli::tests                       # 15
git diff --check
```

限定修改文件的 rustfmt 检查已通过。后续涉及数据面/桌面生命周期时，应按影响运行更完整检查，例如：

```sh
cargo test --locked -p ec-compat --lib
cargo test --locked --features desktop --lib
cargo clippy --locked -p ec-compat --lib -- -D warnings
cargo clippy --locked --features desktop --bins -- -D warnings
```

## 工作区与工具交接

工作区有其他任务已存在的未提交改动：`.github/workflows/build.yml`、`Cargo.lock`、`Cargo.toml`、`README.md`、`src/desktop.rs`、`src/desktop/password.rs`、`src/tun/linux.rs`、`vendor/ec-compat/src/probe.rs`、`vendor/ec-compat/src/trust.rs`，以及新文件 `src/desktop/certificates.rs`。这些不能当成本次断线排查产生的改动，不要直接重置或覆盖。

REA 6.4.0 可通过已有缓存 CLI 使用，无需先改全局 MCP 配置：

```sh
node /Users/class-undefined/.npm/_npx/dea9475797100b20/node_modules/rea-agents/scripts/rea.mjs --help
```

对应技能文件位于该包的 `skills/reverse-engineer-anything/SKILL.md`。本机未发现可用的 Ghidra、Hopper 或 IDA；本轮用 REA 固定文件身份/复用 JS 分析，使用 Xcode `llvm-objdump` 补充原生控制流证据。不要把这一流程说成 REA 已产出完整反编译源码。

`analysis/` 被 git 忽略，以下材料在当前本机工作区可用，换机器/全新 checkout 不会自动获得：

- `analysis/rea-jssdk.json`、`analysis/rea-app.json`：已有静态 JS Evidence，避免重新全量分析。
- `analysis/connection-rea/native/CSClient`、`ECAgent`、`svpnservice`：官方样本副本。ECAgent/svpnservice 通过 macOS 系统授权复制，未运行副本。
- `analysis/connection-rea/*-macho.json`：REA 文件身份及布局证据。
- `analysis/connection-rea/*-disassembly.txt`：同一对象的原生反汇编。
- `analysis/connection-rea/native-findings.md`：完整启动链、报文字段和关键地址。

CSClient SHA-256：`947042c981763a8c5104f5f1ccf95829dc15bf3cc4fe687dcba99de8e52358e4`。
对应 REA Evidence：`ev_29307d67a6cb58cbfe11fb5aaa3c194b5eeb5a7bc7f9b4da06381d3eb7512420`。

## 新会话启动提示

> 请先阅读本文开头与 docs/connection-maintenance.md。0.4.14 已实现正式续期，停止仍在运行的 `hk` VPN 后通过 15 分钟空闲、180 次续期和内网 TCP 验证。应用及后台已安装为 0.4.14，后台 TUN 验证进度见上文；保留工作区其他改动。仍不支持透明会话切换，真实物理断网恢复尚未主动验证。
