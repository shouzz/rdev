# RDev × 飞度网盘：AI Agent 文件中转手册

本文定义 RDev 的设备通道（Device Plane）与飞度网盘开发者 API 的云端工件通道（Artifact Plane）如何协同工作。用户登录飞度网盘后，在 `/rdev` 为一个在线设备创建 5 分钟内可兑换一次的 `fdhc_` 交接，并选择 2、8 或 24 小时委托。Agent 兑换后取得最长 8 小时的 RDev 票据、限定云盘根目录的 `fdpat_` 令牌以及在本次委托绝对截止时间前保持稳定的 `fdrn_` 续签令牌。短租约可以在委托总时长内原地延长，三个凭据值均不变化，已有 SSH、SFTP 和端口转发连接不会因续签中断。RDev 不保存飞度网盘账号密码、Cookie 或长期令牌。

## 1. 能力边界

| 平面 | 入口 | 负责内容 | 不负责内容 |
| --- | --- | --- | --- |
| Device Plane | `https://r.feidu.fit`，SSH 端口由 `/api/config` 返回 | 在线设备、Shell/Exec、SCP/SFTP、Rsync、端口转发、断线重连、设备侧文件 | 飞度网盘目录 ACL、云端长期存储、阿里云签名地址 |
| Artifact Plane | `https://pan.feidu.fit` | `content_id` 范围内的目录浏览、搜索、详情、下载、顺序分片上传、幂等恢复、生命周期、账号绑定云中转状态 | 设备连接、SSH 凭据、RDev 会话 |

存在两条互不替代的路径：AI 使用开发者 API 与 SFTP 时，可以通过 Agent 本地临时目录衔接；登录后的 `/rdev` 文件工作台对大于 `104857600` 字节的文件自动创建账号绑定云中转，设备直接下载或上传阿里云签名 HTTPS 地址。RDev 服务端和飞度应用服务端只传控制、短期凭据与进度，不代理大文件字节。

设备邀请的“保持在线”模式会让受管客户端携带 `--replace-existing` 兑换邀请码。请求设备 ID 已属于同一飞度账号且未撤销时，服务端保留原设备 ID 和首次创建时间，原地轮换设备密钥、提升持久化设备凭据版本、使旧版本签发的全部访问票据失效并断开旧连接；SSH 和浏览器 WebSocket 入口都会校验该版本，服务端重启后仍然拒绝旧票据。不同账号、已撤销设备或未受管在线设备返回 HTTP 409。一次运行模式不请求接管，同名冲突继续分配带数字后缀的新 ID。

## 2. 账号绑定的一次性交接

用户必须先登录 `https://pan.feidu.fit/rdev`，选择委托时长并在目标设备上点击“复制给 AI”。复制内容包含精确设备 ID、`fdhc_` claim、截止时间、委托总时长和正式 Skill 地址，不包含账号密码、Cookie 或长期令牌。

Agent 按复制内容向 `https://pan.feidu.fit${redeem_path}` 发送一次 `POST application/json`：

```json
{"claim":"<运行时 fdhc_ claim>"}
```

必须先确认 HTTP 200，再确认 JSON `code == 0`，随后只读取以下精确字段：

- `data.credentials.device_id`：RDev SSH/SFTP 用户名。
- `data.credentials.rdev_ticket.ticket`：RDev SSH/SFTP 当前运行时密码。
- `data.credentials.developer_token.token`：当前飞度网盘开发者令牌。
- `data.credentials.agent_session.agent_session_id`：后续 heartbeat、续签、撤销和云中转的会话身份。
- `data.credentials.agent_session.renewal_token`：首次兑换返回的 `fdrn_` 令牌；在本次委托的绝对截止时间前保持不变，主动撤销或到期后失效。续签响应可以省略该字段；若返回，必须与首次值逐字节一致。

claim 兑换一次后立即失效；过期、重复兑换或账号/目录权限已经撤销时必须停止并让用户重新创建交接。正式 `rdev-agent` 工具可以把当前会话写入用户本地缓存以支持跨 AI 会话恢复；除此以外，不得把 claim 或兑换响应写入仓库、日志、任务描述、检查点或持久 AI 记忆。

`rdev-agent.py start` 只从标准输入读取 claim；交互终端使用隐藏输入。设备 ID 与 claim 截止时间继续使用普通参数。不得使用 `--claim`，也不得把 claim 拼入 shell 管道文本或进程参数；Agent 应通过子进程标准输入传入运行时值。

## 3. 凭据与运行时约束

RDev 仓库内置正式 Skill `skills/rdev-agent/SKILL.md`、会话工具 `skills/rdev-agent/scripts/rdev-agent.py` 和网盘参考客户端 `tools/feidu-drive.py`，线上提供相同文件：

```bash
curl -fsS https://r.feidu.fit/skills/rdev-agent/scripts/rdev-agent.py -o ./rdev-agent.py
mkdir -p ./tools
curl -fsS https://r.feidu.fit/tools/feidu-drive.py -o ./tools/feidu-drive.py
python3 ./tools/feidu-drive.py --help
```

仅在启动网盘参考客户端的进程环境中注入 `FEIDU_DRIVE_TOKEN`：

```bash
export FEIDU_DRIVE_TOKEN='<从交接响应读取的运行时 fdpat_ 令牌>'
```

- `fdhc_` claim 只用于首次兑换。`rdev-agent.py` 的本地会话文件可以保存 `fdrn_`、当前 RDev 票据和飞度令牌；Windows 使用当前用户 DPAPI 加密整个状态文件，Unix 强制模式 `0600`，撤销后删除。
- RDev 票据只在建立 SSH/SFTP 会话时通过运行时密码通道提供；不要把它写入脚本或连接串。
- 收到飞度 API `401` 时停止任务并请求重新授权；不得换账号、换路径或用相似名称绕过范围。
- 飞度下载接口返回短期 `302`。只对 `Location` 发起不带 `Authorization` 的新请求；不要缓存、记录或转发该 URL。

### 3.1 可续签 Agent 会话

会话接口均使用 `Authorization: Bearer <当前 fdrn_ 令牌>`：

- `POST /agent/v1/sessions/{agent_session_id}/heartbeat`：更新 heartbeat，并返回票据剩余时间、开发者令牌剩余时间、预计传输时间、600 秒最低安全余量、续签时间、绝对截止时间和传输策略。
- `POST /agent/v1/sessions/{agent_session_id}/renew`：使用稳定的 `fdrn_` 原地延长现有 RDev 票据和开发者令牌，响应为 `data.session`，不返回或替换明文凭据。24 小时会话通常在第 8、16 小时附近续期；响应丢失时使用同一个 `fdrn_` 重试。
- `DELETE /agent/v1/sessions/{agent_session_id}`：撤销会话、开发者令牌和 RDev 票据。

凭据必须在到期前维护：只要未超过 `absolute_expires_at_ms` 且会话未撤销，当前 `fdrn_` 可原地延长现有 `rdvat_` 与 `fdpat_` 的到期时间，不改变三个凭据值。过期凭据不能通过续签恢复；预计传输时间加 600 秒大于任一凭据剩余时间时，必须先续签再传输。

## 4. 任务开始：先发现能力和范围

```bash
python3 tools/feidu-drive.py capabilities
python3 tools/feidu-drive.py list --limit 100
```

后续对象身份一律使用返回的真实 `content_id`。不能根据文件名、路径、大小、SHA-1 或大小写推导 ID。

RDev 侧只读取服务端端口配置：

```bash
curl -fsS https://r.feidu.fit/api/config
```

`/api/config` 的 `sshPort` 是当前公网 SSH 端口；SSH 用户名必须使用交接响应中的 `data.credentials.device_id`。Agent 不调用受保护的 `/api/clients`，也不从设备名称或历史记录推导 ID。

## 5. 云盘 → 设备（发布/OTA/工具包）

1. 用 `list` 或 `contents/{content_id}` 确认工件的真实 ID、大小和哈希。
2. 下载到本地临时目录。参考 CLI 会先写 `.part`，完成后原子替换。

   ```bash
   python3 tools/feidu-drive.py download '<content_id>' ./staging/artifact.bin
   sha256sum ./staging/artifact.bin
   ```

3. 默认用 RDev SFTP 推到设备。端口必须使用 `/api/config` 的 `sshPort`，不要硬编码旧端口。

   ```bash
   sftp -P <sshPort> '<deviceId>@r.feidu.fit'
   ssh -p <sshPort> '<deviceId>@r.feidu.fit' 'sha256sum /tmp/artifact.bin'
   ```

   Windows Go 客户端的 SCP 原始字节通道当前只在 `go/v0.2.118-feidu.2` 上完成真实链路实测。交接响应不包含客户端版本，因此默认使用 SFTP。只有从独立可信来源取得精确版本且它等于 `go/v0.2.118-feidu.2` 时才使用 SCP；不能根据相似版本号推断已包含修复。网页 `run.ps1` 和 `run.sh` 会优先下载这个修复版 Windows amd64 客户端，并校验 SHA-256 `5bd964ac75331262ac01e21b79ee3af7322b8e34894d46f281f1a8f0667987bd`。

4. 比较本地和设备端哈希，再执行部署命令。此处是通用 Agent 手工路径；登录网页中大于 `104857600` 字节的文件使用第 8 节的自动云中转。

## 6. 设备 → 云盘（日志/崩溃包/诊断包）

1. 通过 RDev SSH 在设备上生成稳定文件，并记录设备端大小/哈希。

   ```bash
   ssh -p <sshPort> '<deviceId>@r.feidu.fit' 'sha256sum /tmp/diagnostic.tar.zst && stat -c %s /tmp/diagnostic.tar.zst'
   ```

2. 默认用 SFTP 下载到本地，下载完成后再次计算哈希。

   ```bash
   sftp -P <sshPort> '<deviceId>@r.feidu.fit'
   sha256sum ./staging/diagnostic.tar.zst
   ```

3. 上传到令牌允许的目录。大文件使用固定 `operation_id`，这样网络中断后可以安全重试或恢复。

   ```bash
   python3 tools/feidu-drive.py upload ./staging/diagnostic.tar.zst \
     --operation-id '<规范小写 UUID>' \
     --lifecycle archive --lifetime 604800
   ```

4. 记录返回的 `content_id`、`operation_id`、`session_id` 和本地哈希；不要记录任何 `upload_url`。

## 7. 大文件上传和恢复

飞度 API 的参考 CLI 使用顺序分片、并发 1、单片最多 3 次尝试；仅 HTTP `200` 或 `409` 视为分片写入成功。创建请求使用固定 `operation_id` 时，重试会返回原会话，不会产生第二个远端对象。

```bash
python3 tools/feidu-drive.py upload ./staging/ota.img \
  --operation-id '<规范小写 UUID>'
```

进程中断后，保留 `session_id` 和本地文件身份（文件名、大小、修改时间），然后：

```bash
python3 tools/feidu-drive.py resume-upload '<session_id>' ./staging/ota.img
```

恢复前必须重新选择同一文件并通过服务端会话校验；不要手工拼接短期分片 URL。`none`、`hide`、`archive` 是唯一允许的生命周期动作；最大时长为 30 天，`archive` 只做逻辑归档，不物理删除云盘对象。

## 8. 登录工作台的大文件自动云中转

`https://pan.feidu.fit/rdev` 的文件组件使用精确阈值 `104857600` 字节：小于等于阈值继续走 RDev WebSocket 二进制文件通道；大于阈值自动走云中转。

- 浏览器上传到设备：浏览器先以顺序 multipart 直传到飞度网盘；取得真实 `result_content_id` 后，飞度向该账号名下的精确在线设备下发 `cloud_to_device` 任务；设备从飞度领取 302，并直接从阿里云下载到 `<目标文件>.rdev-cloud.part`。完成时核对大小和 SHA-1，再原子发布到目标路径。
- 浏览器从设备下载：飞度下发 `device_to_cloud` 任务；设备核对源文件为普通文件且大小一致，计算 SHA-1，直接顺序 PUT 阿里云分片；飞度完成底层身份核对并写回 `result_content_id` 后，浏览器领取一次性下载票据。

传输状态只允许 `queued`、`running`、`paused`、`completed`、`failed`、`cancelled`。暂停和取消立即使旧 `fdtx_` 设备凭据失效；恢复生成新凭据并重新下发同一个 `transfer_id`。下载断点保留在设备本地 `.rdev-cloud.part`；完整分片在进程重启后先做哈希和原子发布，不发送无效 Range。上传复用同一个 `operation_id` 和 `upload_session_id`，只传服务端仍标记为待传的分片，单片最多三次尝试，只有 HTTP 200 和 409 表示阿里云接受。

每个传输使用从 1 开始单调递增的 `transferGeneration`。飞度向 RDev 下发后，设备必须在 7 秒内完成计划读取和首次 `running` 进度上报；RDev 只有收到同一设备实例、同一 `transfer_id`、同一代次和同一派发 `requestId` 的 ACK 后才在 8 秒内返回 202。飞度控制请求总超时为 10 秒。同代重派不重复执行数据传输，但会为新的 `requestId` 重新 ACK；新代会取消旧代执行上下文。超时或设备失败会进入明确的 `failed`，正式 Agent 的 `--wait` 默认最多自动恢复 2 次，并只在状态变化或每 5% 进度输出，避免 AI 手工高频轮询。

`fdtx_` 明文只存在于飞度到 RDev 再到精确设备的一次下发和设备进程内存。飞度 MySQL 只保存完整令牌的 SHA-256；RDev 不保存令牌；设备不能把 `Authorization` 转发给 302 目标，也不能把签名下载或上传 URL 落盘或写日志。

## 9. RDev 小文件通道的精确消息（浏览器/自研 Agent）

浏览器文件页连接 `wss://<rdev-host>/files`，先发送 JSON `{"op":"auth","deviceId":"<id>","password":"<设备密码>"}`。成功后可使用：

- `{"op":"list","deviceId":"<id>","path":"<目录>","offset":0,"limit":200}`
- `{"op":"upload_start","deviceId":"<id>","taskId":"<任务>","parentPath":"<目录>","name":"<文件名>","size":<字节数>}`
- `{"op":"download_start","deviceId":"<id>","taskId":"<任务>","path":"<文件>","offset":<已接收字节>}`
- `{"op":"upload_end","taskId":"<任务>","path":"<设备路径>","size":<字节数>}`
- `{"op":"cancel","taskId":"<任务>","offset":<当前偏移>}`

文件数据使用二进制帧，不使用 Base64 文本帧。帧头为 `[类型 1 字节][任务 ID 长度 1 字节][任务 ID][偏移 8 字节，大端][负载]`；上传块类型为 `0x20`，上传确认 `0x21`，下载块 `0x22`，传输结束 `0x23`，取消 `0x24`。收到 `upload_ready` 后从服务端给出的 `offset` 继续；收到连接断开时保留任务元数据，重连后重新发送 `upload_start`。这部分协议优先用于浏览器或专用 Agent；命令行自动化优先使用 SSH/SCP/SFTP。

## 10. Agent 安全和可靠性清单

- 每个任务使用 `rdev-agent.py start` 兑换一次性交接，再由工具调用 heartbeat 和 RDev `/api/config`。
- 后续操作先运行 `rdev-agent.py status`；达到 `renewal_due_at_ms` 或安全余量不足时由工具自动续签并原子保存更新后的到期字段，`rdvat_`、`fdpat_` 和 `fdrn_` 在委托期内都保持不变。
- 不调用 RDev `/api/clients`；设备 ID只取 `data.credentials.device_id`。
- 默认使用 SFTP。Windows SCP 只在独立证据确认设备版本精确等于 `go/v0.2.118-feidu.2` 时使用。
- 只使用真实 `content_id`、交接响应的设备 ID和 `/api/config` 返回的 `sshPort`。
- 下载和上传都采用临时文件、大小校验、哈希校验和原子替换。
- 传输失败时只重试当前阶段；不要重新创建云盘对象或并发上传同一会话。
- 任何 URL、日志或错误上报都必须脱敏：claim、RDev 票据、云盘令牌、`Location`、`upload_url` 不得出现。
- 手工路径完成后清理本地临时文件；自动大文件路径不得改回经应用服务器或 Agent 本地代理字节。云盘生命周期按任务设置，不调用物理删除。任务结束运行 `rdev-agent.py revoke`。

## 11. 闭环验收

最小验收应覆盖：

1. 匿名创建交接被拒绝；登录用户创建交接成功；同一 claim 首次兑换成功、第二次兑换失败。
2. `capabilities`、限定根目录遍历和内容详情。
3. 一个小文件云盘下载 → RDev SFTP 上传 → 设备端哈希一致。
4. 一个小文件设备 SFTP 下载 → 云盘上传 → 再下载哈希一致。
5. 中断一个分片后用同一 `operation_id`/`session_id` 恢复，确认没有重复对象。
6. RDev 客户端断线后自动重连；设备同名接管、密钥轮换或撤销后，旧票据建立的活动 SSH 连接被关闭，且旧票据不能重新建立 SSH、浏览器终端、浏览器文件或浏览器桌面连接；服务端重启后仍拒绝旧票据；重新交接后 SSH、SFTP 各执行一次。
7. 使用同一个 `fdrn_` 连续原地延期成功，模拟首个续签响应丢失后重试仍返回相同凭据身份且到期时间不缩短；24 小时委托跨越多个到期前续签窗口，撤销、短租约过期或绝对到期后对应操作都被拒绝。
8. 一个大于 `104857600` 字节的文件完成浏览器直传云盘、设备直下、大小和 SHA-1 核对；中断后复用 `.rdev-cloud.part`。
9. 一个大于 `104857600` 字节的设备文件完成设备直传云盘、浏览器领票下载、大小和 SHA-1 核对；中断后复用原 `upload_session_id`，云端不出现第二个对象。

机器可读的能力清单见 [`ai-agent-manifest.json`](ai-agent-manifest.json)。
