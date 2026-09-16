# RDev × 飞度网盘：固定设备 Token 和文件中转

首次登录飞度网盘授权后，每台设备使用一枚永久、可撤销的 `fdpat_`。同一 Token 用于 SSH、SFTP/SCP、网页终端、设备文件和授权目录内的网盘 API。换 AI 会话、设备或服务器重启、断网重连都不需要新 claim 或人工续租。

## 一次复制和导入

在飞度设备授权页面完成授权并等待服务端持久化确认，然后点击复制完整接入信息。复制的 JSON 严格包含七个字段：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `schema` | string | 固定为 `rdev-device-access.v1` |
| `device_id` | string | 精确设备 ID |
| `rdev_base` | string | RDev HTTPS 服务入口 |
| `api_base` | string | 飞度 HTTPS API 入口 |
| `ssh_host` | string | SSH 主机名或 IP |
| `ssh_port` | integer | SSH 端口 |
| `token` | string | 该设备的固定 `fdpat_` |

不要把复制内容放进聊天、URL、日志、源码、文档或 shell 命令。先下载官方工具，再复制接入信息：

```powershell
curl.exe -fsS https://r.feidu.fit/skills/rdev-agent/scripts/rdev-agent.py -o rdev-agent.py
```

用户在网页复制后，Windows 直接执行下列固定命令；无需粘贴或拆分参数：

```powershell
python rdev-agent.py --import-clipboard
```

工具直接读取剪贴板、使用当前用户 DPAPI 保存，成功后清除同一份剪贴板内容；输出只有非秘密连接信息。Unix 使用 `python3 rdev-agent.py --import-stdin`，经受保护标准输入传入 JSON，保存为权限 `0600` 的文件。不要为了 stdin 把明文拼进命令字符串。网页仅首次交付明文；重开网页不能从摘要取回，丢失时使用已有受保护副本或显式重置。

每台设备保存一个入口；重复导入同一对象不产生新 Token，变更已有入口须显式 `--replace`。Windows 状态根目录为本机当前用户 LocalAppData 下 `Feidu/RDevAgent`，Unix 沿用工具的用户状态目录。文件名根据精确设备 ID 计算，不包含 Token。调用时自动加载，AI 无需读取状态文件或知道 Token。

## 日常使用

只保存一台设备时省略 `--device`。保存多台设备后，使用精确设备 ID：

```bash
python3 rdev-agent.py --device DEVICE-ID status
python3 rdev-agent.py --device DEVICE-ID ssh -- hostname
python3 rdev-agent.py --device DEVICE-ID sftp
python3 rdev-agent.py --device DEVICE-ID sftp --batch-file -
python3 rdev-agent.py --device DEVICE-ID scp-to ./artifact.bin /tmp/artifact.bin
python3 rdev-agent.py --device DEVICE-ID scp-from /tmp/result.bin ./result.bin
python3 rdev-agent.py --device DEVICE-ID drive capabilities
python3 rdev-agent.py --device DEVICE-ID drive list --limit 100
```

`status` 只确认本地已保存的入口，不代表远程设备在线或当前授权健康。远程工作开始时核对真实响应和目标身份，再继续已授权业务。使用复制的 `ssh_host` 和 `ssh_port`，不从主机名猜设备 ID，不调用 `/api/clients`。`/api/config` 仍是管理员检查当前服务端端口的公开入口，但固定工具不会每次连接先依赖 HTTP 发现。

同一 Token 自动注入 SSH/SFTP 的密码通道和网盘客户端的 `FEIDU_DRIVE_TOKEN`。SSH 设置 `ConnectTimeout=10`、`ServerAliveInterval=15`、`ServerAliveCountMax=3`；普通远程命令没有短时执行上限。固定流程没有维护租约的后台线程，飞度网盘离线不终止 SSH。远程命令失败不会自动重放；本地 SSH 退出不能证明远端作业已停止，先检查实际状态再继续。

端口转发由明确参数传入，放在目标之前：

```bash
python3 rdev-agent.py --device DEVICE-ID ssh --local-forward 127.0.0.1:8080:127.0.0.1:80 --no-command
python3 rdev-agent.py --device DEVICE-ID ssh --remote-forward 127.0.0.1:3000:127.0.0.1:3000 --no-command
```

默认使用 SFTP。现代 SCP 也使用 SFTP，不添加 `-O` 强制旧协议。历史 Windows 设备版本 `go/v0.2.121-feidu.16` 已验证该方式；这不是新版本的现场验收证据。

## 网盘文件和大文件中转

先用 `drive capabilities` 确认目录范围和上传/下载能力。对象身份使用真实返回的 `content_id`；不要从名字、路径、大小或哈希推导 ID。

```bash
python3 rdev-agent.py --device DEVICE-ID drive download CONTENT-ID ./staging/artifact.bin
python3 rdev-agent.py --device DEVICE-ID drive upload ./staging/result.bin --operation-id OPERATION-UUID
python3 rdev-agent.py --device DEVICE-ID drive resume-upload UPLOAD-SESSION-ID ./staging/result.bin
```

上传使用一个 `operation_id`、顺序分片、并发 1，重试保留原 `session_id`；只有 HTTP 200 或 409 证明分片被接受。下载签名地址不携带原 Feidu Authorization。手工经本地暂存时，每一跳比较大小和哈希。

大于 `104857600` 字节时，产品自动中转保持设备与存储直接交换字节，RDev/飞度应用服务只处理控制和进度。固定 Token API：

| 操作 | 接口 | 数据 |
| --- | --- | --- |
| 创建 | `POST /developer/v1/rdev/transfers` | `{transfer}` |
| 列表 | `GET /developer/v1/rdev/transfers` | `{items}` |
| 详情 | `GET /developer/v1/rdev/transfers/{transfer_id}` | `{transfer}` |
| 暂停/恢复/取消 | `POST /developer/v1/rdev/transfers/{transfer_id}/pause\|resume\|cancel` | `{transfer}` |

飞度响应使用 HTTP 200 和 `{code:0,data:...}`。创建字段为 `transfer_id`（规范小写 UUID）、`direction`（`cloud_to_device` 或 `device_to_cloud`）、`source_content_id` / `source_path`、`destination_parent_path`、`file_name`、`size_bytes`。账号、设备、根范围均由固定 Token 绑定推导，调用方不提交 AgentSession 或 root。

```bash
python3 rdev-agent.py --device DEVICE-ID transfer create --direction cloud_to_device --source-content-id CONTENT-ID --destination-parent-path /tmp --file-name artifact.bin --size-bytes 104857601 --wait
python3 rdev-agent.py --device DEVICE-ID transfer create --direction device_to_cloud --source-path /tmp/result.bin --file-name result.bin --size-bytes 104857601 --wait
python3 rdev-agent.py --device DEVICE-ID transfer list
python3 rdev-agent.py --device DEVICE-ID transfer status TRANSFER-UUID --wait
python3 rdev-agent.py --device DEVICE-ID transfer resume TRANSFER-UUID
```

当前设备客户端上传不支持改名：`device_to_cloud` 的 `--file-name` 必须与 `--source-path` 的源文件名完全一致（支持 Windows/POSIX 路径），工具和服务端会在创建前拒绝不一致请求。

工具在创建请求前输出非秘密 `transfer_id`，请求响应丢失后仍可查询和恢复原任务。`--wait` 只输出状态变化和每 5% 的进度边界，默认最多自动恢复两次。短暂控制请求失败重试读取；失败或内部凭据跨 24 小时到期，调用固定 Token 的 resume 恢复同一任务。`--auto-resume-attempts 0` 禁用自动恢复。中断后继续 `transfer status UUID --wait`，不另建任务、不索要新 claim。暂停和取消不会自动恢复。只有 `completed` 是成功，`failed`、`cancelled` 或恢复次数用尽返回非零。

内部 `fdtx_` 及其轮换由飞度和设备管理，AI 只持有固定 `fdpat_`。恢复保留原 `transfer_id`、`operation_id` 和上传会话；设备下载断点保留于 `.rdev-cloud.part`。大小/哈希校验通过后原子发布。不要从 HTTP 200 控制响应直接宣称文件传输完成。

## 网页和设备文件协议

本轮固定 Token 网页入口是飞度设备工作台；不代表旧版独立 RDev HTML 页面或原始 VNC/GPU proxy 已支持。WebSocket 握手使用子协议 `rdev-browser-v1` 和 `rdev-access-ticket.<runtime fdpat_>`，再在通道认证消息中发送同一 Token 与同一设备 ID；握手和消息必须一致，凭据不放 URL。文件 WebSocket `/files` 首条认证消息为 `{"op":"auth","deviceId":"<id>","password":"<runtime token>"}`。详情以服务端当前实现为准。

设备文件消息包括 `list`、`upload_start`、`download_start`、`upload_end` 和 `cancel`。目录可使用精确 `location:home` 或 `location:desktop`，不能同时提交非空 `path`；设备返回的语义目录结果才是依据，不拼接桌面路径。

文件数据使用二进制帧：`[类型1字节][任务ID长度1字节][任务ID][偏移uint64大端][负载]`。上传块 `0x20`、上传 ACK `0x21`、下载块 `0x22`、结束 `0x23`、取消 `0x24`。`upload_ready` 后从服务端给出的 offset 继续。命令行任务优先使用现有 SFTP/SCP 封装。

## 授权状态与旧链路兼容

飞度设备页面提供查看和撤销；完成业务、关闭终端或 AI 会话时不撤销。RDev 持久保存设备绑定摘要，可在飞度暂时离线时继续本地认证。飞度发生撤销、账号停用或权限变更后通过控制同步生效；控制通道断开期间不能宣称即时生效，恢复后必须对账。

旧 `fdhc_` 临时 handoff 仍可通过 `start --device ... --claim-expires-at ...` 使用。该兼容路径从兑换响应 `data.credentials.device_id`、RDev ticket、developer token 和 AgentSession 取临时凭据，并通过原 `/agent/v1/sessions/.../heartbeat`、`/renew`、`/transfers` API 维护。它与已导入固定设备访问分开，不能把临时到期规则套在永久 Token 上。

代码、工具和文档镜像必须一致。测试覆盖一次导入、再次运行、同 Token 各通道、重启/重连、撤销对账、跨设备拒绝和原任务恢复；生产完成须另有真实端到端结果，不能把本地测试当作线上验收。
