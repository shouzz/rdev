# 中文设备配置导入

更新（2026-09-28）：本修复已随 `v0.2.121-feidu.23` 部署，公开工具 SHA-256 已回读一致。准确制品、备份和公网测试见 [Windows 启动发布记录](windows-launchers.md)。下方“尚未部署”是 9 月 26 日的历史状态。

`--import-stdin` 读取原始字节，不再依赖 Python 的控制台解码。默认严格 UTF-8，UTF-16/UTF-32 仅在 BOM 明确时接受；最大 65536 字节。错误编码、非法设备 ID 和指定 `--device` 不匹配时，不覆盖原状态，不回显凭据。

Windows 优先 `--import-clipboard`。PowerShell 管道发送 Unicode 前设置 `$OutputEncoding = [System.Text.UTF8Encoding]::new($false)`；不能将编码错误误判为设备离线，也不能按相似 ID 自动纠正。SSH 仍使用准确注册 `id`，不改成 `requestedId` 或 `instanceId`。

Linux 产品工具 34 项测试通过；Windows 真实子进程覆盖中文 ID、UTF-8/BOM/UTF-16/UTF-32、`PYTHONIOENCODING=gbk`、DPAPI 读回，以及错误编码、超限、错误 ID 不覆盖。此为本仓库产品工具测试，与独立安装任务的安全导入脚本分开记录。

本地修复提交 `db8f8c5`，候选服务端 `v0.2.121-feidu.22-db8f8c5`。工具 SHA-256 为 `7a1d2c08fadecbf1abf988a50349b7959ad40df04eb659c3758c29f3e7d7c83c`；服务端二进制 SHA-256 为 `bebcb47d4a6cecca263f6123fe98f3c1a2484ff520ed1f636129ed9f1ea73133`。Go 全量测试与 vet、6 项分发与文档测试通过。

截至本轮尚未部署：对 101.42.185.158 的 SSH 只读检查被自动审批返回 `blocked by policy`，没有绕过。公网工具哈希仍为 `f3cc6745856ab8bbfbb1e980cf7f49cc9c930616a48579783a2f487846503f09`。现场设备与既有 Token 未修改；需要访问策略恢复后备份真实注册表与 host key、核对实际容器和 compose、部署候选并回读公开脚本/清单哈希、完成真实中文 ID 的 SSH 与重连验收。不得把本地测试称作公开分发已更新。
