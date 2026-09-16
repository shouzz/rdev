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
