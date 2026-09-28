# RDev

设备操作与命令：`skills/rdev-agent/SKILL.md`。
文件传输：`docs/ai-agent-artifact-bridge.md`。
接口清单：`docs/ai-agent-manifest.json`。

设备 ID 必须精确匹配，不按显示名或乱码猜测。导入 stdin 必须读取原始字节，以 UTF-8 严格解码；UTF-16/UTF-32 仅在 BOM 明确时接受。Windows 优先 Unicode 剪贴板；非法编码、超限和身份不匹配不得覆盖本地受保护状态。修改工具后同步 web/public 与 internal/server/static 分发副本，执行真实子进程编码测试和 Windows DPAPI 读回。禁止输出凭据，不修改现场设备来掩盖导入错误。

Windows 安装命令必须区分 CMD 和 PowerShell，使用系统绝对路径，首个 HTTPS 请求前启用 TLS 1.2；最低 PowerShell 5.1。变更入口后执行真实 shell 注册和失败退出码测试。Win7 只能分发 go-win7 构建并固定哈希，不得把现代 Windows 模拟系统版本测试当 Win7 实机验收。入口与兼容边界见 docs/windows-launchers.md。
