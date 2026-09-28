# Windows 启动与兼容边界

网页“新增设备”和 `/join` 明确区分 CMD 与 PowerShell。复制的是各自终端可直接执行的一条命令，使用 Windows 系统目录定位 PowerShell，首个 HTTPS 请求前启用 TLS 1.2。注册码只进入当前进程，不进入下载 URL 或脚本文件；编码命令不是加密，不应将含邀请码的命令发到公开日志。

也可下载 `https://r.feidu.fit/run.cmd`，运行后粘贴邀请码。默认保持在线；显式 `-Enroll` 为本次运行，`-Persist` 为保持在线。PowerShell 中执行下载后的文件用 `& '.\run.cmd'`，CMD 中用 `run.cmd`。本地配套 `run-cmd.ps1` 存在时直接执行，否则通过 HTTPS 下载临时入口，结束后清理。只在子进程设置 RemoteSigned，不修改系统执行策略、不绕过组策略。

`run-cmd.ps1` 使用显式命名参数，不把字符串数组当命名开关。服务必须是 HTTPS 源地址，HTTP 只允许环回测试。读取真实 `/api/config` 获取 TCP/KCP 端口。运行失败返回非零；已有设备身份保持不变，重复保持在线不重新注册。

## Windows 7

最低条件是 Windows 7 SP1 + .NET Framework 4.8 + Windows Management Framework 5.1 + 正常 TLS 1.2/根证书。未满足条件先提示，不尝试降级到 TLS 1.0/1.1，不关闭证书校验。

旧系统选择以下独立客户端，下载后核对 SHA-256：

| 架构 | 文件 | SHA-256 |
| --- | --- | --- |
| x64 | rdev-client-windows-win7-amd64.exe | 7e25b7a9e429b4e6aa013f272c51c12566c8c5a7cb804db7917a18135b86e239 |
| x86 | rdev-client-windows-win7-386.exe | ad2ff87eb913763bf676981eb613a164c5fac93a1a64f0b2157c7d92d37402e4 |

工具链沿用仓库 CI 指定的 XTLS/go-win7 `patched-1.26.4`，来源 `https://github.com/XTLS/go-win7/releases/download/patched-1.26.4/go-for-win7-linux-amd64.zip`，下载 SHA-256 `4a8afd5883fe08286edbf31a86dc0dbcc96ce58f54c2aa6ef83adbd8920ade60`。Go 环境固定 `GOTOOLCHAIN=local`，禁止自动换回官方 Go 构建。

## 验证

- `scripts/test-windows-launchers.ps1`：真实 CMD（清空 PATH）、PowerShell 5.1 和 7，中文空格目录，临时注册上线，失败非零，不创建持久身份。
- `scripts/test-persistent-enrollment.ps1`：三台同名隔离安装、重复运行、同身份重连、已消费邀请拒绝。`-LegacyArch amd64|386` 验证对应真实兼容二进制与选择逻辑，不等价于 Windows 7 内核验收。
- 入口实际 HTTP GET/HEAD、缓存和下载头由 Go 测试验证。
- 已有设备的凭据与现场安装不因本次发布更换。

Win7 实机的桌面、PTY、驱动和网络验收尚未完成；不能仅依据脚本解析或现代 Windows 成功宣称全部兼容。
