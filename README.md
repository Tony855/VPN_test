
使用示例
1. 创建新接口

bash
复制
sudo bash wg-manager.sh create wg0 203.0.113.5 51820
输出：

复制
接口 wg0 创建成功，10个初始客户端已生成
配置文件位置：/home/user/wg-configs/wg0-client-1632.conf ...
2. 添加新客户端到wg0

bash
复制
sudo bash wg-manager.sh add-client wg0
输出：

复制
客户端添加成功 → /home/user/wg-configs/wg0-client-1635.conf
3. 验证接口状态

bash
复制
wg show wg0
