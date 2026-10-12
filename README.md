# EasyConnect Rust

[![Build and release](https://github.com/class-undefined/easy-connect/actions/workflows/build.yml/badge.svg)](https://github.com/class-undefined/easy-connect/actions/workflows/build.yml)

独立的 EasyConnect 兼容 Rust 客户端，提供 **GPUI 桌面窗口、系统托盘、TUN 和命令行**，支持 macOS 与 Windows。运行时不依赖官方 APP、后台、Docker 或虚拟机。

界面采用紧凑间距、直角控件、状态摘要和事件日志，支持 URL 和账号密码。记住密码使用 **macOS 钥匙串 / Windows 凭据管理器**，配置 JSON 不存密码。关闭窗口隐藏至托盘并保持连接；托盘支持显示窗口、断开和退出。

这是第三方兼容客户端，并非深信服官方软件。协议引擎和许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 下载与桌面使用

从 [Releases](https://github.com/class-undefined/easy-connect/releases) 下载对应平台：

| 平台 | 架构 | 产物 |
|---|---|---|
| macOS | Apple Silicon / Intel | DMG，内含 EasyConnect Rust.app |
| Windows | x86_64 / aarch64 | ZIP，内含桌面、CLI 与对应架构的 wintun.dll |

macOS 将应用拖入 Applications；Windows 解压后运行 `easy-connect-gui.exe`，保持 CLI 和 `wintun.dll` 在同一目录。

1. 打开应用后自动准备后台服务；首次安装或版本升级时，按系统提示授权管理员权限。底部显示准备进度，完成后提示 **连接环境已就绪**。
2. 输入网关 URL、VPN 账号密码。
3. 点击 **连接**，自动导入资源网段和 DNS。连接中，原按钮变为 **取消连接**。
4. 默认记住密码，保存在 macOS 钥匙串 / Windows 凭据管理器。取消勾选会删除已保存的系统凭据，并关闭自动登录。
5. 默认启用 **启动时自动登录**，可取消勾选，下次打开 GUI 时自动连接已保存的账号；不会重复连接已有会话，也不自动重试失败登录。

连接成功后，主窗口隐藏登录表单，按服务器分组显示资源名称、地址和端口，并提供 **断开连接** 按钮。资源目录来自当前登录会话；目录或字段过长时，会提示已简化显示。断开后恢复登录表单。

底部显示连接状态和连接环境就绪提示。**高级设置**保留修改密码和保存设置；**日志**和**关于**从菜单打开。macOS 提供原生应用、连接、编辑和窗口菜单。macOS / Windows 托盘也可打开主窗口、日志、关于及检查更新。

客户端定期检查当前会话。网关明确报告顶号时，显示“账号已在其他设备登录，本次连接已断开”。管理员断开、会话超时和网络中断分别提示原因，并恢复登录表单。会话结束后等待手动连接，避免自动登录造成反复顶号。

默认在启动时、之后每 12 小时检测本仓库最新正式 GitHub Release，可关闭自动检测或手动检查。发现较新版本会显示下载入口，打开对应 Release 页面；不会静默替换正在运行的客户端。关于页显示开发者「野漫横江 / class-undefined」。发布包同时包含 CLI 和 GUI。

**后续连接无需重复输入 sudo / UAC 密码**。应用自动检查后台版本；新版启动时先断开旧连接并等待清理完成，再更新并启动匹配版本的后台服务。安装或更新时仍需系统管理员授权，无需手动管理后台服务。准备失败时显示原因和重试入口，不会反复弹出授权框。桌面以普通用户运行；后台不保存 VPN 密码到磁盘。

macOS 升级会等待旧 launchd 作业注销、旧进程退出，再替换后台程序。短暂的注册冲突会在同次授权中有限重试；最终失败会保留系统退出码和错误原因。

macOS 发布包使用 `class-undefined` 自签名代码签名证书（非 Apple Developer ID，未公证）；Windows 应用未做商业代码签名，Wintun 使用上游已签名驱动。首次打开需按系统提示允许运行。

## 命令行

通常只需 URL，不需要配置文件：

```sh
easy-connect connect --gateway https://166.111.77.32:4430/
easy-connect resources --gateway https://166.111.77.32:4430/
```

账号密码在本机隐藏输入。安装后台后，普通用户 TUN 连接委托给服务。未安装服务时，macOS 使用 sudo，Windows 在管理员终端连接。

macOS 命令行一次性安装：

```sh
sudo easy-connect install-service --owner "$(id -u)"
```

macOS launchd 标签为 `com.easy-connect.service`，Windows SCM 服务为 `EasyConnectRust`。macOS 使用受保护 Unix socket 并验证服务端 root 身份；Windows 检查监听 PID 与 SCM 一致。随机挑战和双向 HMAC 在传输密码前验证后台身份。凭据通过本地 IPC 和工作进程标准输入传递，不出现在进程参数里。

高级配置与 SOCKS5：

```sh
easy-connect init --gateway https://vpn.example.com --output config/local.json
easy-connect connect --config config/local.json --mode socks
curl --socks5-hostname 127.0.0.1:1080 https://INTRANET_HOST/
```

`--config` 和 `--gateway` 二选一，可调整 MTU、DNS、路由及端点。后台代理使用网关默认参数；手动路由配置需直接在管理员终端运行。其他自签名网关用 `--cert-sha256` 指定已核对的指纹，不自动信任新证书。

脚本可通过 `--credentials-stdin` 安全输入两行账号、密码并关闭输入，不要把明文密码写进 shell 历史或仓库。

## TUN 与路由

TUN 转发 IPv4 TCP、UDP、ICMP，普通应用无需配置代理：

```sh
ping INTERNAL_GATEWAY_IP
curl https://INTRANET_HOST/
```

macOS 使用 utun，Windows 使用 Wintun。外层服务器和物理下一跳被排除，避免递归隧道。安装及登记 DNS 后核验路由，运行中每 3 秒恢复丢失的自有路由，不覆盖其他出口。退出清理路由、DNS 和网卡。

内网域名使用静态 DNS 表或网关 DNS。macOS 使用临时 SystemConfiguration，Windows 使用带进程标记的 NRPT，工作进程结束后后台清理。DNS 的 IPv4 结果按需添加主机路由。不支持 IPv6，内网 AAAA 查询返回空结果。

管理员终端可运行无需 VPN 账号的网卡自测：

```sh
easy-connect tun-self-test
```

它创建临时 TUN 和测试路由，反射系统 ping 检查内核收发，完成后清理，不连接 VPN 网关。

## 构建与发布

需要 Rust 1.94.1 和平台 SDK：macOS Xcode/Command Line Tools；Windows Visual Studio C++ 工具和 Windows SDK。

```sh
cargo build --locked --release --features desktop --bins
cargo test --locked --features desktop --lib
cargo clippy --locked --features desktop --bins -- -D warnings
```

GPUI 0.2.2 使用运行时 Metal 着色器编译，避免独立 Metal 编译工具依赖。仅构建 CLI 可省略 `--features desktop`。

Actions 在 main/PR 上验证并打包四个架构；推送 `v*` 标签，全部构建成功后自动发布 Release、DMG/ZIP 和 SHA-256 清单。Windows 固定下载 Wintun 0.14.1 并验证 SHA-256。产物包含项目、上游和依赖许可证。

## 验证范围

- 已在 M7.6.7R1 网关验证账号密码登录、资源读取、macOS TUN 与内网 ICMP。
- 路由曾在启动后丢失，已加入核验和恢复；新会话已确认完整自动路由，无需手动添加。
- macOS 桌面已启动并完成 GPUI/托盘初始化，密码存储与服务安装需用户本机操作。
- 0.4.6 的取消、资源展示和会话结束逻辑参考已安装的官方 EasyConnect 7.6.7 Web SDK。已用模拟响应验证状态转换；首次升级和真实顶号仍需在测试环境验收。
- Windows 双架构由原生 GitHub runner 编译；真实 VPN 连通和服务安装仍需 Windows 机器验收。
- 不支持验证码/SSO、旧版四通道自动降级、IPv6 或持续自动重连。
- 示例证书指纹由网络观测取得，仅绑定对应 IP 和端口，尚未管理员独立核对；证书变化会拒绝连接。

授权、端口及 ICMP 是否允许仍由网关和目标决定。不会自动停止官方连接，对照测试前请自行断开官方连接。

## 密码策略与改密

兼容网关的临近过期提醒、密码过期和首次强制改密。强制改密时暂停建隧道，在 GUI 点击 **修改密码**；也可从高级设置主动修改。修改成功后同步保存的密码，再重新连接。GUI 修改前需先断开现有连接。

```sh
easy-connect change-password --gateway https://166.111.77.32:4430/
```

命令会分别询问当前密码、新密码和确认密码，不接收明文密码参数。协议依据及验证范围见 [密码策略兼容](docs/password-policy.md)。

## macOS 签名

本地打包默认使用有效签名身份 `class-undefined`（SHA-1 `16CA7F918F2452512BEC526ECFF8561349493198`）。CLI、GUI 与 `.app` 分别签名并严格验证。可用 `MACOS_SIGNING_IDENTITY` 指定其他身份。

GitHub Actions 从 `MACOS_CERTIFICATE_P12`（加密 P12 的 Base64）和 `MACOS_CERTIFICATE_PASSWORD` Secrets 导入临时钥匙串，签名后删除。PR 构建使用 ad-hoc 签名，不读取签名私钥；main / tag 发布构建必须使用配置的证书。
