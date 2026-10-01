# RDev 文件传输

飞度设备页「交给 AI」自动准备接入信息；重复复制复用同一 Token。
[rdev-agent.py](https://r.feidu.fit/skills/rdev-agent/scripts/rdev-agent.py) 支持完整交接文本和七字段 `rdev-device-access.v1` JSON。
Windows 用 `--import-clipboard`，其他系统用 `--import-stdin`；导入后自动保存。

## 设备与网盘

```bash
python rdev-agent.py --device DEVICE-ID scp-to ./file.bin /tmp/file.bin
python rdev-agent.py --device DEVICE-ID scp-from /tmp/file.bin ./file.bin
python rdev-agent.py --device DEVICE-ID drive capabilities
python rdev-agent.py --device DEVICE-ID drive list --limit 100
python rdev-agent.py --device DEVICE-ID drive download CONTENT-ID ./file.bin
python rdev-agent.py --device DEVICE-ID drive upload ./file.bin --operation-id OPERATION-UUID
python rdev-agent.py --device DEVICE-ID drive resume-upload UPLOAD-SESSION-ID ./file.bin
```

网盘对象使用列表返回的 `content_id`。`operation_id` 为上传任务 UUID；恢复使用原上传会话。
工具自动加载设备 Token 并提供给 SSH/SFTP 和网盘 API（`FEIDU_DRIVE_TOKEN`）。

## HTTPS-only SSH 传输

安装 `python -m pip install 'websockets>=15,<17'` 后，在 `ssh`、`scp-to`、`scp-from`、`sftp` 子命令后可显式加入 `--transport wss`。默认 `auto` 先探测 raw SSH banner，不通时选择 WSS；命令开始后不重放。`--transport raw` 保留直连。WSS 使用系统代理配置、TLS 证书校验及原有 SSH 主机密钥校验。仅用于设备 SSH，不改变飞度网盘或网页大文件直传路径。

`/ssh-ws?device=准确ID` 仅携带精确设备 ID；凭据由 `rdev-access-ticket.<credential>` 子协议提供，同时协商 `rdev-browser-v1`。永久 Token 必须具有 `ssh` 能力。浏览器 terminal-only 票据不能使用此入口。内层 SSH 用户名必须与外层设备 ID 相同。

二进制消息最大 65536 字节；空二进制消息表示发送方向 EOF，继续接收返回数据。SSH channel EOF 与退出码仍由 SSH 协议传送。禁止文本帧和压缩。连接限制为每设备 8、全局 128；SSH 握手 15 秒、空闲 90 秒、写入 15 秒、连接最长 24 小时。凭据失效或设备重连后关闭现有连接。

WSS 不接受 TCP、Agent 或 X11 转发，`-L`、`-R`、`-N` 需显式使用 `--transport raw`。HTTP CONNECT 代理必须允许目标 HTTPS 域名及 WebSocket Upgrade；WSS 无法绕过代理自身的域名或协议封锁。不跟随 HTTP 重定向，避免凭据转发。

## 大文件直传与恢复

设备与网盘直接传输，无需经过 AI 本机。网页超过 100 MiB 时自动使用中转。

```bash
python rdev-agent.py --device DEVICE-ID transfer create --direction cloud_to_device --source-content-id CONTENT-ID --destination-parent-path /tmp --file-name file.bin --size-bytes 104857601 --wait
python rdev-agent.py --device DEVICE-ID transfer create --direction device_to_cloud --source-path /tmp/file.bin --file-name file.bin --size-bytes 104857601 --wait
python rdev-agent.py --device DEVICE-ID transfer list
python rdev-agent.py --device DEVICE-ID transfer status TRANSFER-UUID --wait
python rdev-agent.py --device DEVICE-ID transfer resume TRANSFER-UUID
```

上传的 `--file-name` 与源文件名一致。`pause` / `resume` / `cancel` 操作同一任务 UUID。
`--wait` 跟踪进度并最多自动恢复两次；`completed` 表示完成，失败返回非零退出码。
接口为 `/developer/v1/rdev/transfers`；完整字段见[接口清单](https://r.feidu.fit/docs/ai-agent-manifest.json)。
