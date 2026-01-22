#!/bin/bash

export LANG=en_US.UTF-8

# =============================================================
# 用户自定义配置区
# =============================================================
# 你可以在这里修改你想要的客户端配置文件保存路径
MY_PATH="/home/Hy2"
# =============================================================

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# 基础系统判断逻辑 (略，保持原脚本一致)
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

# --- 新增功能：添加新用户 ---
adduser(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then
        red "未检测到 Hysteria 2 安装，请先执行安装选项！"
        return
    fi

    green "开始添加新用户..."
    read -p "请输入新用户名（用于文件夹命名）：" newname
    [[ -z $newname ]] && newname="user_$(shuf -i 100-999 -n 1)"
    read -p "请输入新用户的密码（回车则随机生成）：" newpass
    [[ -z $newpass ]] && newpass=$(date +%s%N | md5sum | cut -c 1-8)

    # 1. 处理服务器配置文件的多用户转换
    # 检查是否已经是列表格式，如果不是，则转换
    if grep -q "password: " /etc/hysteria/config.yaml && ! grep -q "  password:$" /etc/hysteria/config.yaml; then
        # 获取旧密码
        oldpass=$(grep "password: " /etc/hysteria/config.yaml | awk '{print $2}' | head -n 1)
        # 转换为列表格式
        sed -i "s/password: $oldpass/password:\n    - $oldpass/g" /etc/hysteria/config.yaml
    fi
    
    # 追加新密码
    echo "    - $newpass # $newname" >> /etc/hysteria/config.yaml
    
    # 2. 生成新用户专属目录
    user_path="$MY_PATH/$newname"
    mkdir -p "$user_path"
    
    # 3. 提取现有配置信息以生成新客户端配置
    realip
    current_port=$(grep "listen: " /etc/hysteria/config.yaml | awk -F ":" '{print $NF}')
    current_sni=$(grep "sni: " "$MY_PATH/hy-client.yaml" 2>/dev/null | awk '{print $2}')
    [[ -z $current_sni ]] && current_sni="www.bing.com"

    # 生成新用户的 YAML
    cat << EOF > "$user_path/hy-client.yaml"
server: $ip:$current_port
auth: $newpass
tls:
  sni: $current_sni
  insecure: true
fastOpen: true
transport:
  udp:
    hopInterval: 30s 
EOF

    # 生成分享链接
    new_url="hysteria2://$newpass@$ip:$current_port/?insecure=1&sni=$current_sni#Hysteria2-$newname"
    echo "$new_url" > "$user_path/url.txt"

    systemctl restart hysteria-server
    
    green "======================================================"
    green "新用户 $newname 添加成功！"
    yellow "用户配置文件目录: $user_path"
    yellow "专属分享链接:"
    red "$new_url"
    green "======================================================"
}

# --- 核心安装逻辑 (修改了路径部分) ---
insthysteria(){
    # ... (前面的依赖安装逻辑略过)
    realip
    # 下载官方安装器
    wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

    # 询问证书、端口、密码等 (调用原本脚本的函数)
    inst_cert
    inst_port
    inst_pwd
    inst_site

    # 写入服务器配置 (修改为支持列表的基础结构)
    cat << EOF > /etc/hysteria/config.yaml
listen: :$port
tls:
  cert: $cert_path
  key: $key_path
auth:
  type: password
  password:
    - $auth_pwd
masquerade:
  type: proxy
  proxy:
    url: https://$proxysite
    rewriteHost: true
EOF

    # 生成客户端配置到自定义路径
    mkdir -p "$MY_PATH"
    cat << EOF > "$MY_PATH/hy-client.yaml"
server: $ip:$port
auth: $auth_pwd
tls:
  sni: $hy_domain
  insecure: true
fastOpen: true
EOF
    
    url="hysteria2://$auth_pwd@$ip:$port/?insecure=1&sni=$hy_domain#Hysteria2-Default"
    echo $url > "$MY_PATH/url.txt"

    systemctl restart hysteria-server
    green "安装完成！配置已存入 $MY_PATH"
}

# --- 菜单部分 ---
menu() {
    clear
    echo "#############################################################"
    echo -e "#                  ${GREEN}Hysteria 2 多用户版脚本${PLAIN}                  #"
    echo "#############################################################"
    echo -e " 配置文件根路径: ${YELLOW}$MY_PATH${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " ${GREEN}1.${PLAIN} 安装 Hysteria 2"
    echo -e " ${RED}2.${PLAIN} 卸载 Hysteria 2"
    echo " ------------------------------------------------------------"
    echo -e " 3. 关闭、开启、重启 Hysteria 2"
    echo -e " 4. 修改核心配置 (端口/伪装等)"
    echo -e " 5. 查看默认用户配置"
    echo -e " ${GREEN}6.${PLAIN} ${GREEN}添加新用户 (新增功能)${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " 0. 退出脚本"
    echo ""
    read -rp "请输入选项 [0-6]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) # 卸载逻辑增加清理自定义目录
            read -p "是否同时删除自定义配置目录 $MY_PATH ? [y/n]: " del_path
            [[ $del_path == "y" ]] && rm -rf "$MY_PATH"
            # 后面接原卸载逻辑...
            ;;
        3 ) hysteriaswitch ;;
        4 ) changeconf ;;
        5 ) showconf ;;
        6 ) adduser ;;
        0 ) exit 0 ;;
        * ) exit 1 ;;
    esac
}

# 脚本运行入口
menu
