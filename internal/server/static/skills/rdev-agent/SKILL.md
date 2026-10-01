---
name: rdev-agent
description: RDev 远程设备操作：SSH、文件传输、端口转发和飞度网盘。
---

# RDev

飞度设备页「交给 AI」自动准备并复制接入信息。同一设备复用固定 Token。

工具：[rdev-agent.py](https://r.feidu.fit/skills/rdev-agent/scripts/rdev-agent.py)（Python 3.10+、OpenSSH）。
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

## 设备显示名与 RDev 维护

使用经过认证的后端控制 API，不通过 SSH 拼接升级或停止脚本。详见[设备管理](https://r.feidu.fit/docs/device-management.md)。

- 改名：`PATCH /api/control/devices/{精确ID}/name`，JSON 包含实际操作者 `subject` 与 `displayName`。空名称清除覆盖；名称持久化，不改变设备 ID、身份文件或 Token。
- 维护：`POST /api/control/devices/{精确ID}/actions`，JSON 包含 `subject`、当前 `instanceId`、随机 32 位小写十六进制 `requestId` 和 `action`（`upgrade` / `stop` / `uninstall`）。设备须声明 `deviceManagementV1`。
- 查询：同一路径 `GET`，通过 `subject`、`requestId` 查询结果。202 仅为已下发；升级后核对重新连接版本，停止后核对离线。不自动重放失败、未知或服务重启后丢失记录的操作。
- 卸载需显式 `confirm:true` 和客户端本地 `--allow-remote-uninstall`。仅支持标准 Linux systemd 安装；其他系统拒绝。默认保留身份，只有明确要求 `deleteIdentity:true` 才删除配置的身份文件。

控制凭据只放 `X-RDev-Control-Token` HTTPS 请求头，由可信后端保管，不输出、不放 URL、不放浏览器。设备 SSH Token 和浏览器票据不具备此权限。禁止按显示名猜 ID；不得把停止变成撤销身份或禁用下次开机启动。Win7 不使用普通在线升级通道，只接受专用 go-win7 构建和固定哈希。

## HTTPS 代理环境

`ssh`、`scp-to`、`scp-from`、`sftp` 默认 `--transport auto`：执行前探测 raw SSH banner，TCP 不通时使用 `wss://r.feidu.fit/ssh-ws?device=<精确ID>`。可显式选择 `--transport wss` 或 `--transport raw`；命令已经开始后不切换传输、不重放。

WSS 需要 `python -m pip install 'websockets>=15,<17'`，沿用 `https_proxy` / `HTTPS_PROXY` 和 `no_proxy`。代理须允许目标 HTTPS CONNECT 和 WebSocket Upgrade；TLS 证书验证保持开启，重定向禁用。固定 Token 必须有 `ssh` capability，浏览器 terminal-only 票据不能使用此入口。

```bash
python rdev-agent.py --device DEVICE-ID ssh --transport wss -- hostname
python rdev-agent.py --device DEVICE-ID ssh --transport wss -t
python rdev-agent.py --device DEVICE-ID sftp --transport wss --batch-file commands.txt
python rdev-agent.py --device DEVICE-ID scp-to --transport wss ./file.bin /tmp/file.bin
```

WSS 是 OpenSSH 原始字节传输：支持交互 shell（`-t` 强制 PTY）、exec、独立 stderr、真实退出码、SSH channel EOF 和 SFTP。`scp` 使用 OpenSSH 9+ 默认 SFTP 协议；不提供旧版 `scp -O`。工具只接受已声明参数，不把任意 OpenSSH `-o` 透传；host key 使用原 SSH 服务身份并保持 `accept-new` 检查，变更密钥会拒绝。

Windows 设备的 SFTP 批处理绝对路径写成 `/C:/Users/.../file.bin`；`C:/...` 会被 SFTP 当作相对路径。先通过设备实际响应取得目录，不猜测用户名或桌面路径。

WSS 明确禁止 `-L` / `-R` / `-D` / `-N`、Agent/X11 转发；服务端拒绝 direct-tcpip 和 tcpip-forward，即使绕过 CLI 也不能建立监听。需要端口转发时显式使用 `ssh --transport raw`。空二进制消息表示传输写 EOF 并继续读反向数据；WebSocket close 关闭整个传输；单个 SSH channel 的半关闭仍按 SSH 协议处理，不能用 WebSocket close 表示 stdin EOF。

凭据只放 `rdev-access-ticket.<credential>` 子协议请求头；协商结果只返回 `rdev-browser-v1`。代理子进程从运行时环境取凭据，SSH 层使用已绑定身份的 none 认证，不把 Token 发给设备。禁止调试输出请求头。服务端限制：64 KiB 消息、每设备 8 / 总计 128 连接、SSH 握手 15 秒、空闲 90 秒、阻塞写 15 秒、连接最长 24 小时；OpenSSH 每 15 秒 keepalive。撤销、到期或设备实例更换在至多约 1 秒内关闭桥。

## Managed device controls

Managed devices keep a stable device ID while allowing a separate display name. The authenticated control API uses exact IDs:

- PATCH `/api/control/devices/{DEVICE-ID}/name` with `{"subject":"OWNER","displayName":"NAME"}`; GET reads it.
- POST `/api/control/devices/{DEVICE-ID}/actions` with `{"subject":"OWNER","instanceId":"INSTANCE","requestId":"32 lowercase hex chars","action":"upgrade|stop"}`.
- Uninstall is explicit: use `action:"uninstall"`, `confirm:true`, and only when the client was started with `--allow-remote-uninstall`. `deleteIdentity:true` is required only when the protected identity should also be removed.

Action requests are bound to the exact device ID and process instance, are idempotent by request ID, and never replay after a server restart. Upgrade verifies the release SHA-256 before applying it. Stop is one-shot; the client reports its state and exits intentionally. Standard Linux systemd installations support uninstall; other platforms return an explicit unsupported result. Never place a permanent device token in logs or display names.
