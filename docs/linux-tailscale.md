# Linux TUN 与 Tailscale 子网共享

Linux 常开机负责登录 VPN。开发设备通过 Tailscale 使用网关下发的 IPv4 资源。Linux 版本提供 CLI 和 systemd 服务。

## 路由来源与转发

将配置文件中的 `tunnel.share_with_tailscale` 设为 `true`。程序从当前已认证会话下载资源，生成 CIDR，并排除 VPN 外层服务器、物理下一跳和本机虚拟地址。共享资源与 Tailscale 地址段或其他受保护网络重叠时，程序拒绝发布。

程序创建 `ectun0`，安装 IP 路由并启用 IPv4 转发。Tailscale 的默认 SNAT 将转发流量改写为 VPN 虚拟地址，回包由连接跟踪还原。[Tailscale 子网路由文档](https://tailscale.com/docs/features/subnet-routers)

本阶段只使用 IP。Linux 不创建 DNS 代理，也不修改系统或 Tailscale 的 DNS 配置。资源中的 IP、IP 范围和已有静态 IP 记录参与路由生成。只有域名、没有 IP 的资源暂不共享。

程序保留已有的 Tailscale 子网路由。停止时只撤回本次新增的路由。运行状态保存在 `/run/easy-connect/tailscale-routes.json`。systemd 的启动前和退出后清理步骤可处理异常退出遗留的发布状态。

## 安装

主机需要 Linux TUN、iproute2、Tailscale 和 systemd。Tailscale 应先登录。发布子网需要保持 SNAT 开启。Ubuntu 可安装验证工具：

```sh
sudo apt-get install iproute2 iptables iputils-ping
```

源码构建使用 Rust 1.94.1：

```sh
cargo build --locked --release --bin easy-connect
```

生成配置：

```sh
./easy-connect init --gateway https://YOUR_GATEWAY --output profile.json
```

如果使用源码构建，将命令中的 `./easy-connect` 替换为 `target/release/easy-connect`。保留网关证书校验配置，并在生成的 JSON 中加入：

```json
{
  "tunnel": {
    "mtu": 1400,
    "share_with_tailscale": true
  }
}
```

准备 `/etc/easy-connect/credentials`，内容为两行，依次填写账号和密码。该文件及配置文件应由 root 持有，权限为 `600`。systemd 从文件读取标准输入，密码不会进入进程参数或日志。

在解压后的 Linux 包根目录执行：

```sh
sudo ./scripts/install-linux.sh ./easy-connect ./profile.json /etc/easy-connect/credentials
```

源码目录执行时，第一个参数改为 `target/release/easy-connect`。安装脚本部署二进制和服务，启用开机启动。已安装服务会先停止，完成清理后再替换程序。

## Tailscale 路由批准

连接成功后，日志会显示生成的路由数量和 `VPN_SHARED_ROUTES`。在 [Tailscale 设备后台](https://login.tailscale.com/admin/machines) 打开该常开机，进入 **Subnets → Edit**，批准需要使用的网段。按 Tailnet 的现有访问策略授予客户端访问权限。

macOS 和 Windows 默认接收批准的子网路由。Linux 客户端需要启用：

```sh
sudo tailscale set --accept-routes
```

macOS / Windows GUI 可在 **高级设置 → Tailscale 客户端模式**开启子网访问。填写出口主机名或 Tailscale IP，或留空自动检测。应用只检查 Tailscale 出口及路由，不创建本机 VPN 登录会话。

开发设备随后直接使用内网 IPv4 地址。常开机维持唯一的 VPN 登录会话。其他设备再次登录同一 VPN 账号，仍可能触发网关踢出常开机。

## 服务维护

```sh
sudo systemctl status easy-connect
sudo journalctl -u easy-connect -f
sudo systemctl restart easy-connect
sudo systemctl stop easy-connect
```

网络故障先尝试恢复已有会话；恢复耗尽后，systemd 按 20 秒间隔重启。5 分钟内最多启动 3 次。服务器明确结束会话时，CLI 返回 `77`，systemd 停止自动重启，以免与其他设备反复争抢登录。

失败原因解决后，可以执行：

```sh
sudo systemctl reset-failed easy-connect
sudo systemctl start easy-connect
```

手动清理遗留路由：

```sh
sudo easy-connect linux-cleanup
```

## 验证

执行内核自测前，先停止正在运行的 VPN 服务。自测不登录 VPN。转发自测创建临时网络命名空间、veth、NAT 规则和测试路由，退出时清理：

```sh
sudo easy-connect tun-self-test
sudo easy-connect tun-self-test --forwarding
```

2026-10-13 已在 Ubuntu 24.04、x86_64 主机验证：

- Linux CLI 编译、Clippy 和 35 项单元测试通过。
- TUN 本机 ICMP 自测通过。
- 网络命名空间经过 SNAT 到 TUN，再经过反向 NAT 返回的 ICMP 自测通过。
- 实际 VPN 登录成功，命令心跳收到应答，55 条资源 IP 路由发布并获批准。
- macOS 客户端通过 Tailscale 访问网关下发的资源 IP，TCP 建连和 UDP 回包通过。
- TUN 抓包确认客户端流量改写为网关分配的 VPN 虚拟地址。
- 停止服务后撤回本程序发布的路由；重启后恢复发布。

ARM64 构建已加入 CI，尚未在实体 ARM64 主机完成上述运行验证。不同资源可能禁止 ICMP，目标 IP 无 ping 回复不能单独证明 VPN 不通。
