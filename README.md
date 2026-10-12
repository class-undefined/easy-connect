# easy-connect

Rust 编写的独立 EasyConnect 兼容命令行客户端。复用并固定开源 Rust 协议引擎，**运行时不依赖官方 APP、后台服务、Docker 或虚拟机**。

当前为可编译的实验版本：密码认证、RSA 防重放、Cookie 会话、自动读取网关资源组及访问范围、现代 TLS 收发通道、macOS utun、内网路由与临时 split DNS；另外保留用户态 IPv4 网络栈及 SOCKS5 模式。真实账号登录、资源读取和内网 ICMP 已验证；曾遇到启动后网段路由丢失，手工补路由后恢复，现已增加路由核对与自动恢复，更新后需重连验收。

## 编译与公开探测

```sh
cargo build --locked
./target/debug/easy-connect --help
./target/debug/easy-connect discover --config config/tsinghua.example.json
./target/debug/easy-connect discover --config config/tsinghua.example.json --tunnel-handshake
```

第一条 discover 只读取公开认证元数据；`--tunnel-handshake` 另探测不带账号的现代 TLS ServerHello，不申请虚拟 IP，也不建立已认证隧道。

## 连接

常规使用不需要配置文件，只需网关 URL，账号密码在本机输入：

```sh
sudo easy-connect connect --gateway https://166.111.77.32:4430/
easy-connect resources --gateway https://166.111.77.32:4430/
```

默认参数在内存中生成，资源组、网段和 DNS 登录后从网关获取。针对这个已探测的网关内置本次记录的证书指纹；该指纹来自前述网络观测，仍需可信渠道核对。其他网关默认校验公共 CA；自签名证书可通过 `--cert-sha256` 显式指定指纹。不会自动信任新证书，也不会为 URL 模式生成配置文件。

`--config` 保留给调整 MTU、手动路由、DNS 或协议端点等高级用途，与 `--gateway` 二选一。

```sh
cp config/tsinghua.example.json config/local.json
```

默认 `proxy.auto_resources=true`，认证后自动读取 `rclist.csp` 的资源组、默认资源 ID、域名、单个 IPv4、IP 范围与 CIDR/点分掩码，生成访问范围；无需手填校内网段或核心网段。静态 DNS 映射优先使用网关下发的 `Dns data` 表。只有登录后才能确认实际资源名称和范围。

`proxy.route_domains` 与 `proxy.route_ipv4_cidrs` 用于手动补充访问范围；设 `auto_resources=false` 可仅使用手动范围。若网关在配置与资源中均未提供 DNS，`proxy.vpn_dns_servers` 可填写已知内网 DNS 的 IPv4 地址；不会自动把内网名称交给公网 DNS。自动范围是地址/域名过滤，网关仍负责其资源端口和授权策略；未知资源格式会跳过并报告，空范围则拒绝启动。

```sh
./target/debug/easy-connect check-config --config config/local.json
./target/debug/easy-connect resources --config config/local.json --username YOUR_ACCOUNT
sudo ./target/debug/easy-connect connect --config config/local.json --username YOUR_ACCOUNT
```

`resources` 登录、列出网关实际资源组和访问范围，然后注销，不申请虚拟 IP。`connect` 会再次登录。密码在本机隐藏输入，不必发给助手，也不会写入配置。`Ctrl-C` 或 `SIGTERM` 停止服务并尝试注销。

默认 `--mode tun`，需要 sudo 创建并配置 utun。成功后，普通应用会将目标网段的 IPv4 数据包送入隧道，支持 TCP、UDP、ICMP；无需为应用配置代理。外层 VPN 服务器、本机虚拟 IP 和物理下一跳从内网路由中排除，避免递归隧道。既有同名路由冲突时会停止并回滚已经添加的路由，不覆盖原有路由。

客户端在安装路由及登记 DNS 后核对内核实际路由表，运行中每 3 秒检查一次；丢失的自有路由会重新添加并打印 `Restored ... missing TUN routes`。如果路由被其他服务改成不同出口，则不覆盖该冲突路由，会报错停止。清理时同样核对出口，避免删除已被其他服务替换的路由。

内网域名使用网关静态 DNS 表或网关 DNS，并通过临时 SystemConfiguration 键设置分域 DNS。解析出的 IPv4 会按需添加 utun 主机路由。当前仅支持 IPv4，内网 AAAA 查询返回空结果。正常退出会撤销本客户端添加的路由、DNS 配置并关闭网卡；进程被强制结束时，utun 及其路由和临时 DNS 键由系统随会话关闭回收。

自动化可使用 `--credentials-stdin`：从安全凭据提供方通过管道输入恰好两行（账号、密码），随后关闭管道。不要用会将密码记录到 shell 历史中的明文命令。第一次请求失败或断开时返回非零退出码；当前版本由调用方决定重连，没有无限重试密码认证。

```sh
# TUN 连接成功后，在另一个终端测试实际资源中的内网网关 IP
route -n get INTERNAL_GATEWAY_IP
ping -c 3 INTERNAL_GATEWAY_IP
curl https://INTRANET_HOST/
```

`route -n get` 的 interface 应指向本客户端打印的 utun 网卡。能否收到 ping 回应取决于 VPN 网关资源策略及内部目标是否允许 ICMP，不应把单独的 ping 超时当作所有流量都不通。

无需 VPN 账号的本机网卡自测：

```sh
sudo ./target/debug/easy-connect tun-self-test
```

该命令创建临时 utun 和测试地址主机路由，用系统 ping 产生 ICMP，再从 utun 回注正确校验和的回复，检查内核实际收发。它不会连接 VPN 网关；完成后删除临时路由并关闭网卡。当前执行环境没有免密 sudo，所以本次仅执行了无需权限的模拟包转发测试，尚未运行此原生自测。

可选 SOCKS 模式：

```sh
./target/debug/easy-connect connect --mode socks --config config/local.json
curl --socks5-hostname 127.0.0.1:1080 https://INTRANET_HOST/
```

SOCKS 默认监听 `127.0.0.1:1080`，支持 TCP CONNECT 与 IPv4/domain UDP ASSOCIATE（UDP 实际可达性待验证）；拒绝公网监听。客户端不会自动停止官方连接。实际对照验证时应由用户在本机先断开官方连接，避免并发会话限制和结果混淆。

## 网关证据及限制

`https://166.111.77.32:4430/` 本次公开认证探测返回 `M7.6.7R1`、`StartAuth=1`、`RndImg=0`、`MID_ATK_CHECK=0`；密码配置需要初始化 Cookie。

网关 HTTPS 是无 SAN 的自签名证书。示例使用本次观察到的 SHA-256 叶证书指纹：

```text
012fa1b92104a5d514b903a7691e791e890452a499c6980cb590f89016464bb3
```

该指纹从网络初次观测取得，尚未通过管理员独立核对。客户端在每次握手中验证固定叶证书及握手签名。证书更新后会拒绝连接，需要核对新指纹；没有自动信任任何新证书的行为。

旧版 `TIMQ/JJYY/IPCP` 通道与本引擎实现的现代 TLS 通道是两个兼容分支。此网关的现代 TLS 握手公开探测成功，选用 TLS 1.1 / RC4-SHA，与该协议引擎预期一致，证书匹配固定 HTTPS 叶证书。握手成功仍不等于认证后的数据面兼容；虚拟 IP、内网通信均需分别验收。当前没有实现旧版通道自动降级、验证码/SSO、IPv6 或持续自动重连。

代码及许可证来源见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。此前 REA 静态分析见 [analysis/FEASIBILITY.md](analysis/FEASIBILITY.md)。
