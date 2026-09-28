# Windows 接入

设备页复制同一行命令，可在 CMD 或 PowerShell 运行。接入配置自动带入；同一安装保存身份并复用，不要求手填邀请码。

Windows 7 使用独立原生客户端；只调用系统自带工具和 PowerShell 2.0，不要求安装 .NET 4.8、WMF 5.1 或系统补丁。现代 Windows 保持原入口。

公开脚本优先 HTTPS。原版 Win7 不支持当前 HTTPS 引导时，只对公开安装文件使用兼容下载端点。网页固化完整脚本 SHA-256，验证成功才执行；脚本再验证原生客户端完整 SHA-256。注册和客户端连接使用 HTTPS/WSS，兼容证书仅加入程序内存，不改系统证书。

`run.cmd -Server URL -Enroll` 为本次运行，`-Enroll -Persist` 保存身份并配置登录后自动连接；`-IdentityFile` 可指定现有身份。当前 Win7 持久实现是用户登录启动项，不是登录前的系统服务。初次后台启动通过系统自带 PowerShell 2.0 的 ShellExecute 脱离父进程，避免复制命令一直不返回。失败返回非零，包含 Windows 下载器的负 HRESULT。

## Win7 客户端构建

`scripts/build-win7-rtm-client.py --toolchain /path/to/go-win7 --arch amd64|386` 使用 XTLS go-win7 patched-1.26.4 的私有副本，不修改原工具链。脚本固定上游源文件哈希，补齐 RTM 的系统 DLL 和 socket 标志兼容；构建结果必须为对应 Windows PE。

Windows 7/8 程序内补充公开 ISRG Root X1，并沿用机器已有根证书。旧系统使用本机配置的 DNS 服务器直接解析，避免启动负缓存导致恢复网络后长期离线。

| 文件 | SHA-256 |
| --- | --- |
| rdev-client-windows-win7-rtm-amd64.exe | 081247e2610c9798520691a1bb8dab2bbd7b2e0689ab2f711508af67fb7dab88 |
| rdev-client-windows-win7-rtm-386.exe | a5643e183ecb9d5104fa9e718391dc8099998421b883331c78cb9acf4bb8a353 |

## 实测边界

2026-09-29，ESXi 专用 VM86：Windows 7 Enterprise x64 6.1.7600、SP0、PowerShell 2.0、CLR 2.0。已实测原生客户端注册、公开 SSH hostname、524329 字节 SFTP 往返和相同 Token 在重启自动登录后恢复。CMD/PS2 完整下载注册均验证；PS2 初次发现父管道不退出，修复后返回 0 并持续在线。错误脚本哈希返回 1，安装器未执行。32 位客户端仅在该 x64 Win7 的 WOW64 执行过启动检查，尚无独立 32 位系统验收。

测试版本与公开版本必须分别回读，不能把上传二进制、模拟 Windows 版本或网页 fixture 称为安装验收。完整部署记录由发布记录提供。
