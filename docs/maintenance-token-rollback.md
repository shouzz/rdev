# 固定 Token 版本回滚

含永久授权的 `managed_devices.json` 使用 `rdev-device-registry.v4`。旧服务端不能直接读取 v4；切换旧镜像前，要把**当前**注册表转换成 v3。不要直接覆盖成升级前的旧文件，否则会丢失升级后新增的设备、密钥轮换和入网记录。

1. 停止 RDev 服务端，确认没有进程写入该注册表。工具只做离线文件转换，不会停止或启动服务。若准备回退整个功能，还应先暂停飞度侧新增永久授权和授权同步。
2. 在 Linux 服务端执行下列命令，将路径替换为实际挂载数据目录中的文件：

   ```bash
   python3 scripts/maintenance-registry-rollback.py /absolute/rdev-data/managed_devices.json
   ```

3. 检查输出中的 `changed`、设备数量、入网记录数量和 `backup` 路径，再启动已记录的旧镜像，验证设备重连和原有接入方式。

工具先把原始文件逐字节保存为同目录下唯一命名的 `.v4-backup-*.json`，同步写盘后再原子替换注册表。备份和转换后的文件权限均为 `0600`，转换后保留原文件所属用户和组。转换只把 `schema` 改为 v3，并删除各设备的 `maintenance_token`；设备、归属、设备凭据摘要、凭据版本、撤销状态和全部入网记录保持原值。输出不包含授权摘要或 Token。

再次执行已转换的 v3 文件会直接返回 `changed:false`，不改文件，也不创建或覆盖备份。未知格式、重复 JSON 字段和无法用 v3 表达的额外字段会报错并保留原文件。若写盘失败，保留已完成的备份；修正文件系统问题后重试。工具会检测转换过程中已经发生的文件变化，但这不能代替停服。

降为 v3 后，永久 `fdpat_` 不能用于旧 RDev。需要重新启用新版时，在停服状态下恢复**匹配当前设备状态**的 v4 备份，或由新版与飞度重新对账；不能在旧版本又接纳新设备后直接覆盖旧备份，否则同样会丢失后续记录。飞度侧授权及网盘权限不会被这个工具删除。

本地验证：

```bash
python3 -m unittest discover -s scripts -p 'test_maintenance_registry_rollback.py'
go test ./internal/server -run TestMaintenanceRegistryRollback -count=1
```
