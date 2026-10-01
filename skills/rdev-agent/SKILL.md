---
name: rdev-agent
description: RDev 远程设备操作：SSH、文件传输、端口转发和飞度网盘。
---

# RDev

飞度设备页「交给 AI」自动准备并复制接入信息。同一设备复用固定 Token。

工具：[rdev-agent.py](https://r.feidu.fit/skills/rdev-agent/scripts/rdev-agent.py)（Python 3.10+、OpenSSH）。
HTTPS-only 代理环境另安装 `python -m pip install 'websockets>=15,<17'`，使用 `ssh --transport wss`、`scp-to --transport wss`、`scp-from --transport wss` 或 `sftp --transport wss`。默认 `raw` 保留原始 SSH；可显式选择 `auto`，仅探测 SSH banner 后选择传输，不重放命令。WSS 支持系统 HTTPS 代理配置并验证 TLS 证书，不跟随重定向。
WSS 端点为 `/ssh-ws?device=准确ID`，URL 不包含凭据。使用子协议 `rdev-browser-v1` 与 `rdev-access-ticket.<credential>`；永久 Token 必须有 `ssh` 能力。WSS 禁止端口、Agent 和 X11 转发；`-L`、`-R`、`-N` 使用 `--transport raw`。远端端口转发的监听位置仍由现有 RDev SSH 实现决定，WSS 不提供云端到任意主机的 TCP 代理。
Windows：`python rdev-agent.py --import-clipboard`；其他系统：`python3 rdev-agent.py --import-stdin`。
支持完整交接文本或 `rdev-device-access.v1` JSON，导入后自动保存、后续自动复用。

Windows 优先从剪贴板导入。脚本传输使用 UTF-8 字节；stdin 也接受带 BOM 的 UTF-16/UTF-32，不依赖 `PYTHONIOENCODING`。PowerShell 管道发送前需设 `$OutputEncoding = [System.Text.UTF8Encoding]::new($false)`，不要用默认代码页传中文。可用 `--device '准确设备ID' --import-stdin` 核对身份；非法编码或身份不符不会覆盖已存配置。不得输出 Token 或自动猜测、修正设备名。

```bash
python rdev-agent.py --device DEVICE-ID ssh -- hostname
python rdev-agent.py --device DEVICE-ID sftp
python rdev-agent.py --device DEVICE-ID scp-to ./file.bin /tmp/file.bin
python rdev-agent.py --device DEVICE-ID scp-from /tmp/file.bin ./file.bin
python rdev-agent.py --device DEVICE-ID ssh -L 127.0.0.1:8080:127.0.0.1:80 -N
python rdev-agent.py --device DEVICE-ID drive list --limit 100
```

只有一台已保存设备时可省略 `--device`。`status` 查看本地接入信息。
大文件直传和断点恢复见[文件传输](https://r.feidu.fit/docs/ai-agent-artifact-bridge.md)；命令参数见 `--help`。
