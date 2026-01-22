#!/bin/bash
# =========================================================
#                Hysteria 2 一键安装脚本（增强版）
#  - 保留你原有逻辑
#  - 修复：PACKAGE_UPDATE / INSTALL 数组索引调用错误
#  - 新增：菜单 6 新增用户（多用户 userpass）
#  - 安装时默认使用 userpass（admin: 密码）
#  - 自动为每个用户生成独立配置：/root/hy/users/<user>/
# =========================================================

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){ echo -e "\033[31m\033[01m$1\033[0m"; }
green(){ echo -e "\033[32m\033[01m$1\033[0m"; }
yellow(){ echo -e "\033[33m\033[01m$1\033[0m"; }

# 判断系统及定义系统安装依赖方式
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" \
"$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" \
"$(lsb_release -sd 2>/dev/null)" \
"$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" \
"$(grep . /etc/redhat-release 2>/dev/null)" \
"$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

# 确保 curl
if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

inst_cert(){
    green "Hysteria 2 协议证书申请方式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Acme 脚本自动申请"
    echo -e " ${GREEN}3.${PLAIN} 自定义证书路径"
    echo ""
    read -rp "请输入选项 [1-3]: " certInput

    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        chmod a+x /root 2>/dev/null # 让 Hysteria 主程序访问到 /root 目录（部分系统可能不允许 a+x）

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "检测到原有域名：$domain 的证书，正在应用"
            hy_domain=$domain
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi

            read -p "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1

            domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
            if [[ $domainIP == $ip ]]; then
                ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl

                if [[ $SYSTEM == "CentOS" ]]; then
                    ${PACKAGE_INSTALL[int]} cronie
                    systemctl start crond
                    systemctl enable crond
                else
                    ${PACKAGE_INSTALL[int]} cron
                    systemctl start cron
                    systemctl enable cron
                fi

                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc 2>/dev/null

                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

                if [[ -n $(echo $ip | grep ":") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6 --insecure
                else
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure
                fi

                bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc

                if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                    echo $domain > /root/ca.log
                    sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                    echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab

                    green "证书申请成功! cert.crt 与 private.key 已保存到 /root/"
                    yellow "证书crt文件路径: /root/cert.crt"
                    yellow "私钥key文件路径: /root/private.key"
                    hy_domain=$domain
                else
                    red "证书申请似乎失败了：未找到有效的 cert/key"
                    exit 1
                fi
            else
                red "当前域名解析的IP与当前VPS使用的真实IP不匹配"
                green "建议如下："
                yellow "1. 请确保CloudFlare小云朵为关闭状态(仅限DNS), 其他域名解析或CDN网站设置同理"
                yellow "2. 请检查DNS解析设置的IP是否为VPS的真实IP"
                yellow "3. 建议截图发布到 Issues/论坛/TG群询问"
                exit 1
            fi
        fi

    elif [[ $certInput == 3 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path
        yellow "公钥文件 crt 的路径：$cert_path "
        read -p "请输入密钥文件 key 的路径：" key_path
        yellow "密钥文件 key 的路径：$key_path "
        read -p "请输入证书的域名：" domain
        yellow "证书域名：$domain"
        hy_domain=$domain
    else
        green "将使用必应自签证书作为 Hysteria 2 的节点证书"

        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        mkdir -p /etc/hysteria

        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"

        chmod 600 /etc/hysteria/cert.crt /etc/hysteria/private.key

        hy_domain="www.bing.com"
        domain="www.bing.com"
    fi
}

inst_jump(){
    green "Hysteria 2 端口使用模式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 单端口 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 端口跳跃"
    echo ""
    read -rp "请输入选项 [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
        read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport

        if [[ -z "$firstport" || -z "$endport" ]]; then
            red "端口范围不能为空，已取消端口跳跃"
            firstport=""
            endport=""
            return 0
        fi

        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -lt $endport ]]; do
                red "你设置的起始端口必须小于末尾端口，请重新输入"
                read -p "起始端口：" firstport
                read -p "末尾端口：" endport
            done
        fi

        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port 2>/dev/null
        netfilter-persistent save >/dev/null 2>&1
        green "已启用端口跳跃：${firstport}-${endport} -> ${port}"
    else
        yellow "将继续使用单端口模式"
        firstport=""
        endport=""
    fi
}

inst_port(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1

    read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
        read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
        [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    done

    yellow "将在 Hysteria 2 节点使用的端口是：$port"
    inst_jump
}

inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [默认首尔大学]：" proxysite
    [[ -z $proxysite ]] && proxysite="en.snu.ac.kr"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

# ================================
# 多用户：确保 userpass 模式
# ================================
ensure_userpass_mode() {
    local cfg="/etc/hysteria/config.yaml"
    [[ ! -f "$cfg" ]] && red "未发现 $cfg，先安装 Hysteria 2" && return 1

    # 已是 userpass
    if grep -qE '^[[:space:]]*type:[[:space:]]*userpass' "$cfg"; then
        return 0
    fi

    # 从 password 模式迁移到 userpass（把原 password 变成 admin 用户密码）
    if grep -qE '^[[:space:]]*type:[[:space:]]*password' "$cfg"; then
        local oldpass
        oldpass=$(awk '
            $0 ~ /^auth:/ {in_auth=1}
            in_auth && $0 ~ /^[[:space:]]*password:/ {print $2; exit}
        ' "$cfg")

        [[ -z "$oldpass" ]] && red "迁移失败：没读到旧 password" && return 1

        cp -a "$cfg" "${cfg}.bak.$(date +%F_%H%M%S)"

        awk -v p="$oldpass" '
            BEGIN{skip=0}
            /^auth:/{
                print "auth:"
                print "  type: userpass"
                print "  userpass:"
                print "    admin: " p
                skip=1
                next
            }
            skip==1 && /^masquerade:/ {skip=0; print; next}
            skip==1 {next}
            {print}
        ' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"

        green "已将 auth 从 password 自动迁移为 userpass（原密码 -> admin 用户）"
        return 0
    fi

    red "当前 auth 配置不符合预期，无法自动处理（请检查 /etc/hysteria/config.yaml）"
    return 1
}

# ================================
# 菜单6：新增用户（写入 userpass + 生成该用户客户端文件）
# ================================
adduser() {
    local cfg="/etc/hysteria/config.yaml"
    local base="/root/hy"
    local outdir="/root/hy/users"

    ensure_userpass_mode || return 1

    mkdir -p "$outdir" "$base"

    read -rp "输入新用户名（建议字母/数字/_/-，1-32位）：" hy_user
    [[ -z "$hy_user" ]] && red "用户名不能为空" && return 1
    if ! echo "$hy_user" | grep -qE '^[A-Za-z0-9_-]{1,32}$'; then
        red "用户名不合法：仅允许 1-32 位 A-Za-z0-9_-"
        return 1
    fi

    # 查重：4空格 username:
    if grep -qE "^[[:space:]]{4}${hy_user}:" "$cfg"; then
        red "该用户已存在：$hy_user"
        return 1
    fi

    read -rp "设置该用户密码（回车随机）：" hy_pass
    [[ -z "$hy_pass" ]] && hy_pass=$(date +%s%N | md5sum | cut -c 1-10)

    cp -a "$cfg" "${cfg}.bak.$(date +%F_%H%M%S)"

    # 插入到 userpass: 下一行
    awk -v u="$hy_user" -v p="$hy_pass" '
        {print}
        /^[[:space:]]*userpass:[[:space:]]*$/{
            print "    " u ": " p
        }
    ' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"

    systemctl restart hysteria-server >/dev/null 2>&1
    if ! systemctl is-active --quiet hysteria-server; then
        red "新增用户后服务启动失败！请查看：systemctl status hysteria-server"
        return 1
    fi

    # 获取 listen 端口
    local port_now
    port_now=$(awk -F: '/^listen:/{gsub(/ /,"",$0); print $3; exit}' "$cfg")
    [[ -z "$port_now" ]] && port_now="$port"

    # 获取公网 IP
    realip
    local last_ip
    if [[ -n $(echo "$ip" | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip="$ip"
    fi

    # 获取 SNI（优先从现有 hy-client.yaml 读取）
    local sni_now
    sni_now=$(awk '/^[[:space:]]*sni:/{print $2; exit}' /root/hy/hy-client.yaml 2>/dev/null)
    [[ -z "$sni_now" ]] && sni_now="$hy_domain"
    [[ -z "$sni_now" ]] && sni_now="www.bing.com"

    local user_auth="${hy_user}:${hy_pass}"
    local user_dir="${outdir}/${hy_user}"
    mkdir -p "$user_dir"

    cat > "${user_dir}/hy-client.yaml" << EOF
server: ${last_ip}:${port_now}

auth: ${user_auth}

tls:
  sni: ${sni_now}
  insecure: true

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

fastOpen: true

socks5:
  listen: 127.0.0.1:5678

transport:
  udp:
    hopInterval: 30s
EOF

    cat > "${user_dir}/hy-client.json" << EOF
{
  "server": "${last_ip}:${port_now}",
  "auth": "${user_auth}",
  "tls": {
    "sni": "${sni_now}",
    "insecure": true
  },
  "quic": {
    "initStreamReceiveWindow": 16777216,
    "maxStreamReceiveWindow": 16777216,
    "initConnReceiveWindow": 33554432,
    "maxConnReceiveWindow": 33554432
  },
  "socks5": {
    "listen": "127.0.0.1:5678"
  },
  "transport": {
    "udp": {
      "hopInterval": "30s"
    }
  }
}
EOF

    local url="hysteria2://${user_auth}@${last_ip}:${port_now}/?insecure=1&sni=${sni_now}#Hy2-${hy_user}"
    echo "$url" > "${user_dir}/url.txt"

    green "用户新增成功：$hy_user"
    yellow "该用户配置已生成："
    yellow "  ${user_dir}/hy-client.yaml"
    yellow "  ${user_dir}/hy-client.json"
    yellow "  ${user_dir}/url.txt"
    red "分享链接：$(cat ${user_dir}/url.txt)"
}

insthysteria(){
    warpv6=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    warpv4=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $warpv4 =~ on|plus || $warpv6 =~ on|plus ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
        realip
        systemctl start warp-go >/dev/null 2>&1
        wg-quick up wgcf >/dev/null 2>&1
    else
        realip
    fi

    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps iptables-persistent netfilter-persistent

    wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

    if [[ -f "/usr/local/bin/hysteria" ]]; then
        green "Hysteria 2 安装成功！"
    else
        red "Hysteria 2 安装失败！"
        exit 1
    fi

    # 询问用户 Hysteria 配置
    inst_cert
    inst_port
    inst_pwd
    inst_site

    mkdir -p /etc/hysteria

    # 设置 Hysteria 配置文件（默认启用多用户 userpass：admin）
    cat << EOF > /etc/hysteria/config.yaml
listen: :$port

tls:
  cert: $cert_path
  key: $key_path

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

auth:
  type: userpass
  userpass:
    admin: $auth_pwd

masquerade:
  type: proxy
  proxy:
    url: https://$proxysite
    rewriteHost: true
EOF

    # 最终入站端口范围（用于生成分享链接显示）
    if [[ -n $firstport ]]; then
        last_port="$port,$firstport-$endport"
    else
        last_port=$port
    fi

    # 给 IPv6 地址加中括号
    if [[ -n $(echo $ip | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip=$ip
    fi

    mkdir -p /root/hy

    # 生成 admin 的客户端配置（userpass：auth=admin:password）
    cat << EOF > /root/hy/hy-client.yaml
server: $last_ip:$last_port

auth: admin:$auth_pwd

tls:
  sni: $hy_domain
  insecure: true

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

fastOpen: true

socks5:
  listen: 127.0.0.1:5678

transport:
  udp:
    hopInterval: 30s 
EOF

    cat << EOF > /root/hy/hy-client.json
{
  "server": "$last_ip:$last_port",
  "auth": "admin:$auth_pwd",
  "tls": {
    "sni": "$hy_domain",
    "insecure": true
  },
  "quic": {
    "initStreamReceiveWindow": 16777216,
    "maxStreamReceiveWindow": 16777216,
    "initConnReceiveWindow": 33554432,
    "maxConnReceiveWindow": 33554432
  },
  "socks5": {
    "listen": "127.0.0.1:5678"
  },
  "transport": {
    "udp": {
      "hopInterval": "30s"
    }
  }
}
EOF

    url="hysteria2://admin:$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain#Hysteria2-admin"
    echo $url > /root/hy/url.txt

    systemctl daemon-reload
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl start hysteria-server

    if systemctl is-active --quiet hysteria-server && [[ -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务启动成功"
    else
        red "Hysteria 2 服务启动失败，请运行 systemctl status hysteria-server 查看服务状态并反馈，脚本退出"
        exit 1
    fi

    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成（多用户模式 userpass）"
    yellow "默认用户：admin"
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
    red "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
    red "$(cat /root/hy/hy-client.json)"
    yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/url.txt"
    red "$(cat /root/hy/url.txt)"
}

unsthysteria(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1

    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh

    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1

    green "Hysteria 2 已彻底卸载完成！"
}

starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
    green "已启动 Hysteria 2"
}

stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
    yellow "已关闭 Hysteria 2"
}

hysteriaswitch(){
    yellow "请选择你需要的操作："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
    echo ""
    read -rp "请输入选项 [0-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
}

changeport(){
    oldport=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 1p | awk '{print $2}' | awk -F ":" '{print $2}')

    read -p "设置 Hysteria 2 端口[1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
        read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
        [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    done

    sed -i "1s#$oldport#$port#g" /etc/hysteria/config.yaml
    sed -i "s#:${oldport}#:${port}#g" /root/hy/hy-client.yaml 2>/dev/null
    sed -i "s#:${oldport}#:${port}#g" /root/hy/hy-client.json 2>/dev/null

    stophysteria && starthysteria

    green "Hysteria 2 端口已成功修改为：$port"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

changepasswd(){
    # 兼容 userpass：默认改 admin 的密码；若你想改其他用户，用“新增用户”再自行修改 yaml
    ensure_userpass_mode || return 1

    oldpasswd=$(awk '
        /^[[:space:]]*userpass:[[:space:]]*$/ {in=1; next}
        in && /^[[:space:]]{4}admin:/ {print $2; exit}
    ' /etc/hysteria/config.yaml)

    read -p "设置 admin 用户的新密码（回车随机）：" passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-10)

    cp -a /etc/hysteria/config.yaml "/etc/hysteria/config.yaml.bak.$(date +%F_%H%M%S)"

    # 替换 admin 密码
    awk -v p="$passwd" '
        /^[[:space:]]{4}admin:/ {$2=p; print; next}
        {print}
    ' /etc/hysteria/config.yaml > /etc/hysteria/config.yaml.tmp && mv /etc/hysteria/config.yaml.tmp /etc/hysteria/config.yaml

    # 同步更新默认输出的 /root/hy/hy-client.*（admin）
    sed -i "s#auth: admin:${oldpasswd}#auth: admin:${passwd}#g" /root/hy/hy-client.yaml 2>/dev/null
    sed -i "s#\"auth\": \"admin:${oldpasswd}\"#\"auth\": \"admin:${passwd}\"#g" /root/hy/hy-client.json 2>/dev/null
    sed -i "s#hysteria2://admin:${oldpasswd}@#hysteria2://admin:${passwd}@#g" /root/hy/url.txt 2>/dev/null

    stophysteria && starthysteria

    green "admin 用户密码已成功修改"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

change_cert(){
    old_cert=$(cat /etc/hysteria/config.yaml | grep -E '^[[:space:]]*cert:' | awk -F " " '{print $2}')
    old_key=$(cat /etc/hysteria/config.yaml | grep -E '^[[:space:]]*key:' | awk -F " " '{print $2}')
    old_hydomain=$(cat /root/hy/hy-client.yaml 2>/dev/null | grep sni | awk '{print $2}')

    inst_cert

    sed -i "s!$old_cert!$cert_path!g" /etc/hysteria/config.yaml
    sed -i "s!$old_key!$key_path!g" /etc/hysteria/config.yaml
    [[ -n "$old_hydomain" ]] && sed -i "s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.yaml 2>/dev/null
    [[ -n "$old_hydomain" ]] && sed -i "s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.json 2>/dev/null

    stophysteria && starthysteria

    green "Hysteria 2 节点证书类型已成功修改"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

changeproxysite(){
    oldproxysite=$(cat /etc/hysteria/config.yaml | grep url | awk -F " " '{print $2}' | awk -F "https://" '{print $2}')

    inst_site

    # 你的原脚本这里改的是 /etc/caddy/Caddyfile，但你当前方案未必有 caddy
    if [[ -f /etc/caddy/Caddyfile ]]; then
        sed -i "s#$oldproxysite#$proxysite#g" /etc/caddy/Caddyfile
        green "已同步修改 /etc/caddy/Caddyfile"
    fi

    # 修改 /etc/hysteria/config.yaml 的伪装网站（更靠谱）
    sed -i "s#https://$oldproxysite#https://$proxysite#g" /etc/hysteria/config.yaml

    stophysteria && starthysteria
    green "Hysteria 2 节点伪装网站已成功修改为：$proxysite"
}

changeconf(){
    green "Hysteria 2 配置变更选择如下:"
    echo -e " ${GREEN}1.${PLAIN} 修改端口"
    echo -e " ${GREEN}2.${PLAIN} 修改 admin 密码（多用户模式）"
    echo -e " ${GREEN}3.${PLAIN} 修改证书类型"
    echo -e " ${GREEN}4.${PLAIN} 修改伪装网站"
    echo ""
    read -p " 请选择操作 [1-4]：" confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        * ) exit 1 ;;
    esac
}

showconf(){
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
    red "$(cat /root/hy/hy-client.yaml 2>/dev/null)"
    yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
    red "$(cat /root/hy/hy-client.json 2>/dev/null)"
    yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/url.txt"
    red "$(cat /root/hy/url.txt 2>/dev/null)"
    yellow "（多用户新增用户目录：/root/hy/users/）"
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#                  ${GREEN}Hysteria 2 一键安装脚本${PLAIN}                  #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} ${GREEN}安装 Hysteria 2${PLAIN}"
    echo -e " ${RED}2.${PLAIN} ${RED}卸载 Hysteria 2${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " 3. 关闭、开启、重启 Hysteria 2"
    echo -e " 4. 修改 Hysteria 2 配置"
    echo -e " 5. 显示 Hysteria 2 配置文件"
    echo -e " 6. 新增用户（多用户 userpass）"
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
        * ) exit 1 ;;
    esac
}

menu