# 来源与许可证

本项目的 Rust CLI 复用 `Axfff/hkustgz-connect` 的独立协议引擎，不调用官方 EasyConnect、ECAgent 或 svpnservice。

- 引擎来源：https://github.com/Axfff/hkustgz-connect
- 固定提交：`fa6c6c49aaac38cf127951cf6256c4e0d36a5dc8`
- 路径：`vendor/ec-compat`
- 引擎许可证：`GPL-3.0-only AND AGPL-3.0-only`。本项目也按这个组合表达式提供。
- 完整许可证和上游来源说明保留于 `vendor/ec-compat/LICENSES`、`LICENSE`、`NOTICE.md`、`PROVENANCE.md`、`THIRD_PARTY_NOTICES.md`。
- 本地修改：显式 HTTPS 叶证书 SHA-256 指纹校验；将该校验用于认证及现代隧道令牌连接；认证后的资源 XML 读取接口；隧道令牌获取延迟到建立隧道时；认证后配置失败时尝试注销。协议数据面与用户态网络栈继续来自固定的上游版本。本项目另外实现资源组、网段与静态 DNS 的自动导入。
- TUN 修改：给数据面增加只用于 shutdown 的 socket 句柄接口，以便退出时打断阻塞的收发线程。macOS TUN 使用 `tun-rs` 2.8.11，SystemConfiguration 使用 `system-configuration` 及其 sys 绑定，依赖原许可证由各 crate 保留。本项目实现资源路由规划、回滚、IPv4/ICMP 转发和临时 split DNS。

另参考 `sing-easyconnect` 提交 `50752d75289cf2755b343d290b879c0c99857731` 的协议文档，了解旧版与新版通道区别；没有将该项目的 Go 实现或握手二进制纳入运行代码。

TLS 指纹验证器保留 TLS 握手签名校验，以固定叶证书身份替代公共 CA、主机名和证书有效期检查；指纹错误时拒绝连接。所附网关指纹是本次公开网络观测结果，应通过可信渠道核对。没有全局关闭证书校验的选项。
