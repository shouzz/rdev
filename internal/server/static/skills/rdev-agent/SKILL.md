---
name: rdev-agent
description: RDev 远程设备操作：SSH、文件传输、端口转发和飞度网盘。
---

# RDev

飞度设备页「交给 AI」自动准备并复制接入信息。同一设备复用固定 Token。

工具：[rdev-agent.py](https://r.feidu.fit/skills/rdev-agent/scripts/rdev-agent.py)（Python 3.10+、OpenSSH）。
Windows：`python rdev-agent.py --import-clipboard`；其他系统：`python3 rdev-agent.py --import-stdin`。
支持完整交接文本或 `rdev-device-access.v1` JSON，导入后自动保存、后续自动复用。

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
