# 中文设备配置导入

`--import-stdin` 读取原始字节，不再依赖 Python 的控制台解码。默认严格 UTF-8，UTF-16/UTF-32 仅在 BOM 明确时接受；最大 65536 字节。错误编码、非法设备 ID 和指定 `--device` 不匹配时，不覆盖原状态，不回显凭据。

Windows 优先 `--import-clipboard`。PowerShell 管道发送 Unicode 前设置 `$OutputEncoding = [System.Text.UTF8Encoding]::new($false)`；不能将编码错误误判为设备离线，也不能按相似 ID 自动纠正。SSH 仍使用准确注册 `id`，不改成 `requestedId` 或 `instanceId`。

Linux 产品工具 34 项测试通过；Windows 真实子进程覆盖中文 ID、UTF-8/BOM/UTF-16/UTF-32、`PYTHONIOENCODING=gbk`、DPAPI 读回，以及错误编码、超限、错误 ID 不覆盖。此为本仓库产品工具测试，与独立安装任务的安全导入脚本分开记录。

上线状态以本次生产制品与公网脚本哈希回读为准；没有部署证据前不宣称公开分发已更新。
