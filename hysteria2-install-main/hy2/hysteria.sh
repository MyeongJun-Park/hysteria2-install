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

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

# --- 1. 基础功能函数 (必须放在调用者之前) ---

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
        # 确保目录存在
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
    yellow "使用的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入伪装网站地址 (默认首尔大学): " proxysite
    [[ -z $proxysite ]] && proxysite="en.snu.ac.kr"
}

# --- 2. 核心业务函数 ---

adduser(){
    if [[ ! -f /etc/hysteria/config.yaml ]]; then
        red "未检测到 Hysteria 2 安装，请先执行选项 1"
        return
    fi
    green "开始添加新用户..."
    read -p "请输入新用户名：" newname
    [[ -z $newname ]] && newname="user_$(shuf -i 100-999 -n 1)"
    read -p "请输入新用户密码：" newpass
    [[ -z $newpass ]] && newpass=$(date +%s%N | md5sum | cut -c 1-8)

    # 转换多用户格式 (YAML 列表)
    if grep -q "password: " /etc/hysteria/config.yaml && ! grep -q "  password:$" /etc/hysteria/config.yaml; then
        oldpass=$(grep "password: " /etc/hysteria/config.yaml | awk '{print $2}' | head -n 1)
        sed -i "s/password: $oldpass/password:\n    - $oldpass/g" /etc/hysteria/config.yaml
    fi
    echo "    - $newpass # $newname" >> /etc/hysteria/config.yaml
    
    user_path="$MY_PATH/$newname"
    mkdir -p "$user_path"
    realip
    current_port=$(grep "listen: " /etc/hysteria/config.yaml | awk -F ":" '{print $NF}')
    
    cat << EOF > "$user_path/hy-client.yaml"
server: $ip:$current_port
auth: $newpass
tls:
  sni: www.bing.com
  insecure: true
EOF
    echo "hysteria2://$newpass@$ip:$current_port/?insecure=1&sni=www.bing.com#$newname" > "$user_path/url.txt"
    systemctl restart hysteria-server
    green "新用户 $newname 添加成功！配置已存至: $user_path"
}

insthysteria(){
    realip
    # 强制重新下载安装器
    wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

    # 这里的函数已经在前面定义过了，不会再报错
    inst_cert
    inst_port
    inst_pwd
    inst_site

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

    mkdir -p "$MY_PATH"
    cat << EOF > "$MY_PATH/hy-client.yaml"
server: $ip:$port
auth: $auth_pwd
tls:
  sni: $hy_domain
  insecure: true
EOF
    echo "hysteria2://$auth_pwd@$ip:$port/?insecure=1&sni=$hy_domain#Default" > "$MY_PATH/url.txt"

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl restart hysteria-server
    green "Hysteria 2 安装并配置完成！"
}

showconf(){
    yellow "配置保存根路径: $MY_PATH"
    if [[ -f $MY_PATH/url.txt ]]; then
        red "默认连接链接: $(cat $MY_PATH/url.txt)"
    else
        red "尚未生成配置，请先运行安装。"
    fi
}

# --- 3. 菜单入口 ---

menu() {
    clear
    echo "#############################################################"
    echo -e "#                  Hysteria 2 多用户管理脚本                #"
    echo "#############################################################"
    echo -e " 配置文件存储位置: ${YELLOW}$MY_PATH${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " ${GREEN}1.${PLAIN} 安装/覆盖安装 Hysteria 2"
    echo -e " ${RED}2.${PLAIN} 彻底卸载 Hysteria 2"
    echo " ------------------------------------------------------------"
    echo -e " 3. 重启 Hysteria 服务"
    echo -e " 4. 查看默认用户配置"
    echo -e " ${GREEN}5.${PLAIN} ${GREEN}添加新用户 (多密码)${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " 0. 退出脚本"
    echo ""
    read -rp "请输入选项 [0-5]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) systemctl stop hysteria-server; rm -rf /etc/hysteria "$MY_PATH"; green "卸载完成" ;;
        3 ) systemctl restart hysteria-server; green "重启成功" ;;
        4 ) showconf ;;
        5 ) adduser ;;
        0 ) exit 0 ;;
        * ) exit 1 ;;
    esac
}

menu
