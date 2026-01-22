#!/bin/bash
# =========================================================
# Hysteria 2 一键安装脚本（最终版 v2 - 多用户安全版）
# 1) 安装默认 userpass：admin
# 2) 菜单6 新增用户（生成 /root/hy/users/<user>/）
# 3) 自动修复证书/私钥权限（适配 systemd User=hysteria）
# 4) 新增用户重启失败自动回滚配置
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

# ================================
# 修复 TLS 证书权限（关键：适配 systemd User=hysteria）
# ================================
fix_tls_perm() {
    local cfg="/etc/hysteria/config.yaml"
    [[ ! -f "$cfg" ]] && return 0

    local cert key dir
    cert=$(awk '/^[[:space:]]*cert:/{print $2; exit}' "$cfg")
    key=$(awk '/^[[:space:]]*key:/{print $2; exit}' "$cfg")
    [[ -z "$cert" || -z "$key" ]] && return 0
    [[ ! -f "$cert" || ! -f "$key" ]] && return 0

    dir="$(dirname "$cert")"

    # 如果存在 hysteria 用户，则按 hysteria 用户运行的服务权限设置
    if id hysteria >/dev/null 2>&1; then
        chown -R root:hysteria "$dir" 2>/dev/null
        chmod 750 "$dir" 2>/dev/null

        chown root:hysteria "$cert" "$key" 2>/dev/null
        chmod 644 "$cert" 2>/dev/null
        chmod 640 "$key" 2>/dev/null
    else
        # 兜底：root 跑
        chown root:root "$cert" "$key" 2>/dev/null
        chmod 644 "$cert" 2>/dev/null
        chmod 600 "$key" 2>/dev/null
        chmod 755 "$dir" 2>/dev/null
    fi
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
        chmod a+x /root 2>/dev/null

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
                    hy_domain=$domain
                else
                    red "证书申请失败：未找到有效的 cert/key"
                    exit 1
                fi
            else
                red "当前域名解析的IP与当前VPS使用的真实IP不匹配"
                yellow "请确保 DNS 解析到真实 IP（关闭 Cloudflare 代理小云朵）"
                exit 1
            fi
        fi

    elif [[ $certInput == 3 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path
        read -p "请输入密钥文件 key 的路径：" key_path
        read -p "请输入证书的域名：" domain
        hy_domain=$domain
    else
        green "将使用必应自签证书作为 Hysteria 2 的节点证书"
        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        mkdir -p /etc/hysteria

        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"

        # 注意：最终权限由 fix_tls_perm 统一修
        chmod 600 /etc/hysteria/private.key
        chmod 644 /etc/hysteria/cert.crt

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
            yellow "端口范围为空，取消端口跳跃"
            firstport=""; endport=""
            return 0
        fi
        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -lt $endport ]]; do
                red "起始端口必须小于末尾端口，请重新输入"
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
        firstport=""; endport=""
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
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-10)
    yellow "默认用户 admin 的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址（去除https://） [默认首尔大学]：" proxysite
    [[ -z $proxysite ]] && proxysite="en.snu.ac.kr"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

# ================================
# 多用户：确保 userpass 模式（若是 password 自动迁移）
# ================================
ensure_userpass_mode() {
    local cfg="/etc/hysteria/config.yaml"
    [[ ! -f "$cfg" ]] && red "未发现 $cfg，先安装 Hysteria 2" && return 1

    if grep -qE '^[[:space:]]*type:[[:space:]]*userpass' "$cfg"; then
        return 0
    fi

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
                print "    admin: \"" p "\""
                skip=1
                next
            }
            skip==1 && /^masquerade:/ {skip=0; print; next}
            skip==1 {next}
            {print}
        ' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"

        green "已将 auth 从 password 迁移为 userpass（原密码 -> admin）"
        return 0
    fi

    red "当前 auth 配置不符合预期，无法自动处理（请检查 /etc/hysteria/config.yaml）"
    return 1
}

# ================================
# 菜单6：新增用户（安全版：失败回滚 + 自动修TLS权限）
# ================================
adduser() {
    local cfg="/etc/hysteria/config.yaml"
    local outdir="/root/hy/users"

    ensure_userpass_mode || return 1
    mkdir -p "$outdir"

    read -rp "输入新用户名（建议字母/数字/_/-，1-32位）：" hy_user
    [[ -z "$hy_user" ]] && red "用户名不能为空" && return 1
    if ! echo "$hy_user" | grep -qE '^[A-Za-z0-9_-]{1,32}$'; then
        red "用户名不合法：仅允许 1-32 位 A-Za-z0-9_-"
        return 1
    fi

    if grep -qE "^[[:space:]]{4}${hy_user}:" "$cfg"; then
        red "该用户已存在：$hy_user"
        return 1
    fi

    read -rp "设置该用户密码（回车随机）：" hy_pass
    [[ -z "$hy_pass" ]] && hy_pass=$(date +%s%N | md5sum | cut -c 1-10)

    # 备份配置，便于失败回滚
    local bak="${cfg}.bak.$(date +%F_%H%M%S)"
    cp -a "$cfg" "$bak" || { red "备份失败：$bak"; return 1; }

    # 写入用户（密码加引号，避免特殊字符炸 YAML）
    awk -v u="$hy_user" -v p="$hy_pass" '
        {print}
        /^[[:space:]]*userpass:[[:space:]]*$/{
            print "    " u ": \"" p "\""
        }
    ' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"

    # 自动修 TLS 权限，避免 systemd User=hysteria 读取失败
    fix_tls_perm

    # 重启服务
    systemctl restart hysteria-server >/dev/null 2>&1
    if ! systemctl is-active --quiet hysteria-server; then
        red "新增用户后服务启动失败！正在自动回滚配置..."
        cp -a "$bak" "$cfg"
        fix_tls_perm
        systemctl restart hysteria-server >/dev/null 2>&1
        systemctl status hysteria-server --no-pager -l
        return 1
    fi

    # 生成用户文件
    local port_now sni_now ip2 last_ip user_auth user_dir
    port_now=$(awk -F: '/^listen:/{gsub(/ /,"",$0); print $3; exit}' "$cfg")
    [[ -z "$port_now" ]] && port_now="24443"

    ip2=$(curl -s4m8 ip.sb -k || curl -s6m8 ip.sb -k)
    if echo "$ip2" | grep -q ":"; then last_ip="[$ip2]"; else last_ip="$ip2"; fi

    sni_now=$(awk '/^[[:space:]]*sni:/{print $2; exit}' /root/hy/hy-client.yaml 2>/dev/null)
    [[ -z "$sni_now" ]] && sni_now="www.bing.com"

    user_auth="${hy_user}:${hy_pass}"
    user_dir="${outdir}/${hy_user}"
    mkdir -p "$user_dir"

    cat > "${user_dir}/hy-client.yaml" <<EOF
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

    cat > "${user_dir}/hy-client.json" <<EOF
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

    echo "hysteria2://${user_auth}@${last_ip}:${port_now}/?insecure=1&sni=${sni_now}#Hy2-${hy_user}" > "${user_dir}/url.txt"

    green "用户新增成功：$hy_user"
    yellow "已生成：${user_dir}/"
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

    [[ -f "/usr/local/bin/hysteria" ]] && green "Hysteria 2 安装成功！" || { red "Hysteria 2 安装失败！"; exit 1; }

    inst_cert
    inst_port
    inst_pwd
    inst_site

    mkdir -p /etc/hysteria /root/hy

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
    admin: "$auth_pwd"

masquerade:
  type: proxy
  proxy:
    url: https://$proxysite
    rewriteHost: true
EOF

    # 端口展示：若开启跳跃，链接里显示 24443,10000-20000
    if [[ -n $firstport ]]; then
        last_port="$port,$firstport-$endport"
    else
        last_port="$port"
    fi

    if [[ -n $(echo $ip | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip="$ip"
    fi

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

    echo "hysteria2://admin:$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain#Hysteria2-admin" > /root/hy/url.txt

    # 关键：启动前修复证书权限（适配 User=hysteria）
    fix_tls_perm

    systemctl daemon-reload
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl restart hysteria-server

    if systemctl is-active --quiet hysteria-server; then
        green "Hysteria 2 服务启动成功"
    else
        red "Hysteria 2 服务启动失败："
        systemctl status hysteria-server --no-pager -l
        exit 1
    fi

    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成（多用户 userpass）"
    yellow "默认用户：admin"
    yellow "YAML：/root/hy/hy-client.yaml"
    yellow "JSON：/root/hy/hy-client.json"
    yellow "URL ：/root/hy/url.txt"
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
    fix_tls_perm
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
    oldport=$(awk -F: '/^listen:/{gsub(/ /,"",$0); print $3; exit}' /etc/hysteria/config.yaml 2>/dev/null)

    read -p "设置 Hysteria 2 端口[1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
        read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
        [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    done

    # 替换 listen 行的端口
    sed -i "s/^listen: :${oldport}$/listen: :${port}/" /etc/hysteria/config.yaml

    stophysteria && starthysteria
    green "Hysteria 2 端口已成功修改为：$port"
}

changepasswd(){
    ensure_userpass_mode || return 1

    oldpasswd=$(awk '
        /^[[:space:]]*userpass:[[:space:]]*$/ {in=1; next}
        in && /^[[:space:]]{4}admin:/ {print $2; exit}
    ' /etc/hysteria/config.yaml)

    read -p "设置 admin 用户的新密码（回车随机）：" passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-10)

    cp -a /etc/hysteria/config.yaml "/etc/hysteria/config.yaml.bak.$(date +%F_%H%M%S)"

    awk -v p="$passwd" '
        /^[[:space:]]{4}admin:/ {$2="\""p"\""; print; next}
        {print}
    ' /etc/hysteria/config.yaml > /etc/hysteria/config.yaml.tmp && mv /etc/hysteria/config.yaml.tmp /etc/hysteria/config.yaml

    stophysteria && starthysteria
    green "admin 用户密码已成功修改"
}

change_cert(){
    inst_cert
    # 替换 config.yaml 中 cert/key
    sed -i "s|^[[:space:]]*cert:.*$|  cert: $cert_path|" /etc/hysteria/config.yaml
    sed -i "s|^[[:space:]]*key:.*$|  key: $key_path|" /etc/hysteria/config.yaml

    fix_tls_perm
    stophysteria && starthysteria
    green "证书已修改并生效"
}

changeproxysite(){
    inst_site
    sed -i "s|^[[:space:]]*url: https://.*$|    url: https://$proxysite|" /etc/hysteria/config.yaml
    stophysteria && starthysteria
    green "伪装网站已修改并生效"
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
    yellow "默认 admin 配置：/root/hy/"
    yellow "YAML: /root/hy/hy-client.yaml"
    yellow "JSON: /root/hy/hy-client.json"
    yellow "URL : /root/hy/url.txt"
    red "$(cat /root/hy/url.txt 2>/dev/null)"
    echo ""
    yellow "多用户目录：/root/hy/users/"
    ls -1 /root/hy/users 2>/dev/null | sed 's/^/ - /'
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