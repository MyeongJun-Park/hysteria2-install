#!/bin/bash

export LANG=en_US.UTF-8

# =============================================================
# 用户自定义配置区
# =============================================================
# 修改这里即可改变客户端配置文件保存的路径
MY_PATH="/home/Hy2"
# =============================================================

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){ echo -e "\033[31m\033[01m$1\033[0m"; }
green(){ echo -e "\033[32m\033[01m$1\033[0m"; }
yellow(){ echo -e "\033[33m\033[01m$1\033[0m"; }

# 1. 基础环境检测 (保留原版)
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

# --- 2. 核心配置函数 (已移至上方，确保调用不报错) ---

inst_cert(){
    green "Hysteria 2 协议证书申请方式如下："
    echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 自定义证书路径"
    read -rp "请输入选项 [1-2]: " certInput
    if [[ $certInput == 2 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path
        read -p "请输入密钥文件 key 的路径：" key_path
        read -p "请输入证书的域名：" hy_domain
    else
        green "将使用必应自签证书"
        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        mkdir -p /etc/hysteria
        openssl ecparam -genkey -name prime256v1 -out "$key_path"
        openssl req -new -x509 -days 36500 -key "$key_path" -out "$cert_path" -subj "/CN=www.bing.com"
        hy_domain="www.bing.com"
    fi
}

inst_port(){
    read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    yellow "使用的端口是：$port"
}

inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车则随机）：" auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
}

inst_site(){
    read -rp "请输入伪装网站地址 (默认首尔大学): " proxysite
    [[ -z $proxysite ]] && proxysite="en.snu.ac.kr"
}

# --- 3. 多用户及展示函数 ---

adduser(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then
        red "未检测到安装，请先选 1 安装 Hysteria 2！"
        return
    fi
    green "开始添加新用户..."
    read -p "请输入新用户名：" newname
    [[ -z $newname ]] && newname="user_$(shuf -i 100-999 -n 1)"
    read -p "请输入新用户密码：" newpass
    [[ -z $newpass ]] && newpass=$(date +%s%N | md5sum | cut -c 1-8)

    # 转换配置文件为列表格式（如果还不是的话）
    if grep -q "password: " /etc/hysteria/config.yaml && ! grep -q "  password:$" /etc/hysteria/config.yaml; then
        oldpass=$(grep "password: " /etc/hysteria/config.yaml | awk '{print $2}' | head -n 1)
        sed -i "s/password: $oldpass/password:\n    - $oldpass/g" /etc/hysteria/config.yaml
    fi
    echo "    - $newpass # $newname" >> /etc/hysteria/config.yaml
    
    user_path="$MY_PATH/$newname"
    mkdir -p "$user_path"
    realip
    current_port=$(grep "listen: " /etc/hysteria/config.yaml | awk -F ":" '{print $NF}')
    current_sni=$(grep "sni: " "$MY_PATH/hy-client.yaml" 2>/dev/null | awk '{print $2}' | head -n 1)
    [[ -z $current_sni ]] && current_sni="www.bing.com"

    cat << EOF > "$user_path/hy-client.yaml"
server: $ip:$current_port
auth: $newpass
tls:
  sni: $current_sni
  insecure: true
fastOpen: true
EOF
    echo "hysteria2://$newpass@$ip:$current_port/?insecure=1&sni=$current_sni#$newname" > "$user_path/url.txt"
    systemctl restart hysteria-server
    green "新用户 $newname 添加成功！配置文件在: $user_path"
}

showconf(){
    yellow "所有配置文件保存在: $MY_PATH"
    if [[ -f $MY_PATH/url.txt ]]; then
        green "默认用户分享链接:"
        red "$(cat $MY_PATH/url.txt)"
    fi
}

# --- 4. 主安装逻辑 ---

insthysteria(){
    realip
    # 保持原版依赖安装
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode iptables-persistent netfilter-persistent
    
    # 运行原版安装脚本（Misaka原版）
    wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

    # 调用上方定义的配置函数
    inst_cert
    inst_port
    inst_pwd
    inst_site

    # 生成服务器配置 (兼容多用户列表格式)
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

    # 生成默认客户端配置到自定义路径
    mkdir -p "$MY_PATH"
    cat << EOF > "$MY_PATH/hy-client.yaml"
server: $ip:$port
auth: $auth_pwd
tls:
  sni: $hy_domain
  insecure: true
fastOpen: true
EOF
    echo "hysteria2://$auth_pwd@$ip:$port/?insecure=1&sni=$hy_domain#Default" > "$MY_PATH/url.txt"

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl restart hysteria-server
    green "Hysteria 2 安装并配置成功！"
    showconf
}

# --- 5. 主菜单 ---

menu() {
    clear
    echo "#############################################################"
    echo -e "#                  Hysteria 2 增强版管理脚本                #"
    echo "#############################################################"
    echo -e " 客户端配置存储目录: ${YELLOW}$MY_PATH${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " ${GREEN}1.${PLAIN} 安装/覆盖安装 Hysteria 2"
    echo -e " ${RED}2.${PLAIN} 彻底卸载 Hysteria 2"
    echo " ------------------------------------------------------------"
    echo -e " 3. 重启 Hysteria 服务"
    echo -e " 4. 查看当前配置信息"
    echo -e " ${GREEN}5. 添加新用户 (多密码管理)${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " 0. 退出脚本"
    echo ""
    read -rp "请输入选项 [0-5]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) systemctl stop hysteria-server; rm -rf /etc/hysteria "$MY_PATH"; green "卸载完成" ;;
        3 ) systemctl restart hysteria-server; green "服务已重启" ;;
        4 ) showconf ;;
        5 ) adduser ;;
        0 ) exit 0 ;;
        * ) exit 1 ;;
    esac
}

menu
