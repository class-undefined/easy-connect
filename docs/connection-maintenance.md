# 连接维护与官方行为证据

0.4.9 将连接维护放在隧道传输层。正常连接不请求门户状态接口。传输故障触发会话确认，并尝试恢复已有通道。服务器明确返回注销原因时，客户端结束会话。

## 官方客户端的行为

分析对象是本机 EasyConnect 7.6.7、build 6。证据包括随应用发布的 JavaScript、原生程序机器码和历史运行日志。机器码通过 Xcode 的 `llvm-objdump` 检查，未运行复制出的官方程序。

| 证据位置 | 已确认的行为 |
| --- | --- |
| `Web/jssdk/api/res.js` 的 `checkLoginStatus` | 有 ECAgent 时默认查询本地 `DoQueryService`，命令为 `QUERY LOGINSTATUS`。无 ECAgent 或指定 `byServer` 时才访问门户。 |
| `Web/jssdk/business/logout.js` 的 `registLoginStatusEvent` | 状态查询成功后，用定时器更新本地状态。默认间隔 1 秒；`validTime >= 30` 时改为 10 秒。 |
| `Web/local/vpn_status_manager/vpn_status_manager.js` | 区分离线、在线、连接中、注销和会话切换。普通查询错误回调记录错误，不直接注销。 |
| `svpnservice`，`0x10010c8db` 至 `0x10010c977` | 命令线程按 1 秒等待可读事件。空闲计数超过 30 后，在 5 的倍数处发送命令 3。 |
| `svpnservice`，`0x10011b4d0`、`0x100115310` | 命令 3 使用已有会话绑定材料。旧版传输包含 `JJYY` 标记和命令结构。 |
| `svpnservice`，`0x100117b30`、`0x10011b3af` | 命令回复 15 表示心跳。旧版服务器结构为 40 字节，含 4 字节标记。 |
| `svpnservice`，`0x100110aa1`、`0x1001105e0`、`0x100111f10` | 发送空闲超过 30 秒后，构建并发送 76 字节 ICMP echo。旧版路径额外包装 IPCP。 |
| `svpnservice`，`0x100112150`、`0x10010a084` | 接收线程识别 ICMP echo reply，并重置心跳计数。 |
| `svpnservice`，`0x10010cac0`、`0x10010cc70` | 存在命令恢复、重新建通道和通知收发线程重新建立连接的路径。 |

`svpnservice` 副本的 SHA-256：

```text
9f521455bb3349545c5ab7e7a00bfe1f2191e181c7eb8d515b4ef17867eb681e
```

历史日志 `/Library/Logs/Sangfor/EasyConnect/L3VPN.log` 提供运行证据：

- 第 41054～41075 行：发送心跳出现 `Broken pipe`，命令心跳仍正常。随后发送通道重新建立。
- 第 52566～52585 行：收到重连事件，命令恢复收到 `SERVER_RESET`。约 5 秒后重新建立命令、发送和接收通道。

这些日志证明对应路径曾执行，不能证明所有重试阈值和触发条件。用户侧 `CSClient` 的 5 秒 IPC 心跳与 VPN 协议心跳分属不同连接。

## 本项目的实现

`engine/data_plane.rs` 维护命令、发送和接收通道。命令线程等待 socket 可读事件，空闲约 35 秒时发送协议心跳。发送线程在空闲约 31 秒时发送 ICMP 保活包。真实发送会推迟下一次数据保活。

命令心跳等待回复，并处理分段或合并的命令消息。数据心跳识别与当前会话匹配的 echo reply。只有网关曾成功回复数据心跳，客户端才启用数据回复超时判断。任何合法入站 IPv4 流量都能解除待确认状态。

通道故障触发一次门户查询。查询在线或查询失败时，传输层继续恢复。只有明确会话结束或恢复耗尽，连接才退出。恢复复用现有 token，保留虚拟地址，不重新提交账号密码。

发送或接收故障只重建对应通道。命令恢复先发送命令 1；服务器返回重置时，尝试命令 0。命令通道恢复成功后，客户端关闭旧收发 socket，让收发线程重新建通道。返回的地址必须与当前地址相同，否则退出并清理原网卡、DNS 和路由。

接收通道重建时，丢弃旧连接残留的 IPv4 半包。每次 TLS 重建使用独立加密状态。关闭连接会中断心跳等待、重试退避和已登记 socket 的 TLS 握手。新 socket 会替换登记项，避免只关闭旧连接。

SOCKS 和 TUN 共用上述维护逻辑。退出时关闭传输，再回收后台维护线程。GUI 仍读取本地服务状态；这属于界面状态同步，不会产生门户轮询。

## 兼容性适配与本地策略

本项目使用真实 TLS 封装。官方样本使用旧版 TLS 外观与 IPCP 封装。命令 3、回复 15 和 ICMP 内容来自官方样本；将命令投射到已有 64 字节请求和 36 字节回复结构，属于兼容性适配。

现有 TLS 收发和地址请求格式还参考了 [zju-connect v1.1.1 的协议实现](https://github.com/Mythologyli/zju-connect/blob/v1.1.1/client/easyconnect/protocol.go)。该实现没有补齐本轮的原生命令心跳，不能作为心跳运行验证。

以下数值是本项目的策略，不能称为官方常量：

| 策略 | 当前值 |
| --- | --- |
| 命令心跳回复等待 | 10 秒。已开始的 TLS record 读取还受 socket 超时限制。 |
| 确认支持后的数据回复等待 | 95 秒。后续保活发送不会延长原截止时间。 |
| 每次通道恢复的次数 | 3 次。 |
| 恢复尝试前的等待 | 依次 3 秒、5 秒和 10 秒。 |
| 恢复连接与 TLS socket 超时 | 最多 5 秒；关闭可中断已登记 socket。尚未完成的 TCP connect 受连接超时限制。 |

数据回复超时只重开接收通道。收到新通道流量后继续工作。网关从未回复数据心跳时，接收通道依靠真实 I/O 错误和 TCP keepalive 判定故障；此时尚不能主动识别所有接收黑洞。

## 验证与测试边界

自动化测试覆盖保活包字段与校验和、分段命令应答、回复超时、服务器重置、同会话恢复、地址变化拒绝和 IPv4 半包清理。还覆盖替换 socket 的关闭、取消退避、门户查询失败和健康连接不查询门户。

```sh
cargo test --locked -p ec-compat --lib
cargo test --locked --features desktop --lib
cargo clippy --locked -p ec-compat --lib -- -D warnings
cargo clippy --locked --features desktop --bins -- -D warnings
```

测试使用模拟传输和本地 socket，没有自动登录真实网关，也没有人为踢出真实会话。TLS 命令心跳与恢复请求仍需真实网关验证。测试时先观察空闲连接，再测试网络短暂中断及恢复。日志中的 `VPN command heartbeat confirmed` 和 `VPN data heartbeat confirmed` 分别证明当前网关回复了对应探测。

若出现故障，保留 `VPN Control channel failed`、`recovery attempt` 和 `channel recovered` 日志。它们用于区分协议不兼容、网络故障和恢复失败，不输出 token 或原始报文。
