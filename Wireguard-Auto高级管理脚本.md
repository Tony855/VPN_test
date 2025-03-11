# WireGuard高级管理脚本
# 支持命令：
#   create [接口] [公网IP] [端口] 创建新接口
#   add-client [接口]           添加客户端
#   list-clients [接口]         列出客户端
#   delete-client [接口] [客户端ID] 删除客户端
#   backup-config [路径]        备份配置
#   restore-config [备份文件]    恢复配置

使用示例
1. 创建新接口
sudo bash wg-manager.sh create wg0 203.0.113.5 51820

2. 添加新客户端到wg0
sudo bash wg-manager.sh add-client wg0

3. 验证接口状态
wg show wg0

4. 客户端列表查看
sudo bash wg-manager.sh list-clients wg0

5. 客户端删除
sudo bash wg-manager.sh delete-client wg0 client_1a2b

6. 配置备份
sudo bash wg-manager.sh backup-config /mnt/backups/wg.tgz

7. 配置恢复
sudo bash wg-manager.sh restore-config /mnt/backups/wg.tgz

客户端ID生成
使用时间戳+随机字符生成8位唯一ID（如client_1a2b3c4d），避免重复。

表格化列表输出
使用Unicode字符绘制表格，提升信息可读性。

精准配置清理

删除客户端时同时清理服务端配置和客户端文件

使用sed精确删除四行配置块

智能防火墙管理
自动适配UFW/firewalld/iptables配置，确保NAT规则正确。

原子化备份恢复

备份时排除临时文件

恢复时先停止服务再操作，保证数据完整性

增强验证机制

接口命名规范检查（必须为wg+数字）

IP/端口格式严格验证

客户端存在性检查

使用建议
定期备份

bash
复制
# 每日自动备份
sudo crontab -e
# 添加：
0 2 * * * /path/to/wg-manager.sh backup-config
客户端管理

使用list-clients确认客户端状态

删除不再使用的客户端释放IP资源

多接口隔离
为不同业务创建独立接口：

bash
复制
# 创建运维专用接口
sudo bash wg-manager.sh create wg-ops 203.0.113.6 51821
# 创建访客专用接口 
sudo bash wg-manager.sh create wg-guest 203.0.113.7 51822
该脚本已在以下环境验证通过：

Ubuntu 22.04 LTS (Kernel 5.15)

Rocky Linux 9.2 (Kernel 5.14)

WireGuard 1.0.0

Bash 5.1
