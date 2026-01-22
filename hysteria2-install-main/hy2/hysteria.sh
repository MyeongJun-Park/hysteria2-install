#!/bin/bash

export LANG=en_US.UTF-8

# =============================================================
# 用户自定义配置区
# =============================================================
MY_PATH="/home/Hy2"
# =============================================================

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){ echo -e "\033[31m\033[01m$1\033[0m"; }
green(){ echo -e "\033[32m\033[01m$1\033[0m"; }
yellow(){ echo -e "\033[33m\033[01m$1\033[0m"; }

# 

# --- 基础环境检测与原版函数 (保留) ---
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

# ... (此处省略中间原有的 inst_cert, inst_port 等 200 行函数代码，保持不变) ...

# --- 新增：多用户添加函数 ---
adduser(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then
        red "请先安装 Hysteria 2！"
        return
    fi
    green "--- 添加新用户 ---"
    read -p "用户名: " newname
    [[ -z $newname ]] && newname="user_$(shuf -i 100-999 -n 1)"
    read -p "密码: " newpass
    [[ -z $newpass ]] && newpass=$(date +%s%N | md5sum | cut -c 1-8)

    # 转换配置文件为多密码列表格式
    if grep -q "password: " /etc/hysteria/config.yaml && ! grep -q "  password:$" /etc/hysteria/config.yaml; then
        oldpass=$(grep "password: " /etc/hysteria/config.yaml | awk '{print $2}' | head -n 1)
        sed -i "s/password: $oldpass/password:\n    - $oldpass/g" /etc/hysteria/config.yaml
    fi
    echo "    - $newpass # $newname" >> /etc/hysteria/config.yaml
    
    # 在自定义路径生成该用户的配置
    user_dir="$MY_PATH/$newname"
    mkdir -p "$user_dir"
    lip=$(curl -s4m8 ip.sb -k || curl -s6m8 ip.sb -k)
    lport=$(grep "listen: " /etc/hysteria/config.yaml | awk -F ":" '{print $NF}')
    
    cat << EOF > "$user_dir/hy-client.yaml"
server: $lip:$lport
auth: $newpass
tls:
  sni: www.bing.com
  insecure: true
EOF
    echo "hysteria2://$newpass@$lip:$lport/?insecure=1&sni=www.bing.com#$newname" > "$user_dir/url.txt"
    systemctl restart hysteria-server
    green "用户 $newname 已添加！配置：$user_dir"
}

# --- 修改后的安装函数 (关键路径替换) ---
insthysteria(){
    # ... (原版检测逻辑) ...
    
    # 核心修改点：将所有 /root/hy 替换为 $MY_PATH
    mkdir -p "$MY_PATH"
    
    # (此处省略原版安装逻辑，但在生成文件时使用以下路径)
    # cat << EOF > $MY_PATH/hy-client.yaml
    # cat << EOF > $MY_PATH/hy-client.json
    # echo $url > $MY_PATH/url.txt

    # ... (原版启动逻辑) ...
    
    showconf
}

# --- 修改后的显示函数 ---
showconf(){
    yellow "Hysteria 2 配置文件已保存到 $MY_PATH"
    red "默认客户端配置 (YAML): $(cat $MY_PATH/hy-client.yaml 2>/dev/null)"
    red "节点分享链接: $(cat $MY_PATH/url.txt 2>/dev/null)"
}

# --- 增强版主菜单 ---
menu() {
    clear
    echo "#############################################################"
    echo -e "#                  Hysteria 2 增强管理脚本                  #"
    echo "#############################################################"
    echo -e " 客户端配置存储目录: ${YELLOW}$MY_PATH${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " ${GREEN}1.${PLAIN} 安装 Hysteria 2 (保留原版全部逻辑)"
    echo -e " ${RED}2.${PLAIN} 卸载 Hysteria 2"
    echo " ------------------------------------------------------------"
    echo -e " 3. 关闭、开启、重启服务"
    echo -e " 4. 修改 Hysteria 2 配置"
    echo -e " 5. 显示当前配置信息"
    echo -e " ${GREEN}6. 添加新用户 (多密码管理)${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " 0. 退出脚本"
    echo ""
    read -rp "请输入选项 [0-6]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) unsthysteria ;;
        3 ) hysteriaswitch ;;
        4 ) changeconf ;;
        5 ) showconf ;;
        6 ) adduser ;;
        * ) exit 0 ;;
    esac
}

menu
