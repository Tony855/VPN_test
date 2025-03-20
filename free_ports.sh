#!/bin/bash

# 脚本功能：强制释放除 SSH(22) 外的所有占用端口
# 警告：会终止非系统关键服务，谨慎使用！

# 检查 root 权限
if [ "$(id -u)" != "0" ]; then
  echo -e "\033[31m错误：请使用 sudo 或以 root 用户运行此脚本\033[0m"
  exit 1
fi

# 定义要排除的端口列表（逗号分隔）
EXCLUDE_PORTS="22,53,80,443"

# 查找并终止占用进程
echo -e "\n\033[34m=== 正在扫描非关键端口占用情况 ===\033[0m"
ss -tulnp | awk -v exclude="$EXCLUDE_PORTS" '
  BEGIN {
    split(exclude, ports, ",")
    for (i in ports) exclude_ports[ports[i]] = 1
  }
  /LISTEN/ {
    split($5, a, ":")
    port = a[length(a)]
    if (!exclude_ports[port]) {
      pid = $7
      gsub(/.*pid=/, "", pid)
      gsub(/,.*/, "", pid)
      if (pid ~ /^[0-9]+$/) {
        print "终止进程: 端口 " port " (PID " pid ")"
        system("kill -9 " pid)
      }
    }
  }
'

# 验证结果
echo -e "\n\033[34m=== 剩余非排除端口占用情况 ===\033[0m"
ss -tulnp | grep -E -v "$(echo $EXCLUDE_PORTS | sed 's/,/\\|/g')" | awk '{printf "端口: %-10s 进程: %s\n", $5, $7}'

echo -e "\n\033[32m操作完成！\033[0m"
