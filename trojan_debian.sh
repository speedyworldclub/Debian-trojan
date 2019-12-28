#!/bin/bash
if [[ $(id -u) != 0 ]]; then
    echo Please run this script as root.
    exit 1
fi
#######设置信息颜色############
ERROR="31m"      # Error message
SUCCESS="32m"    # Success message
WARNING="33m"   # Warning message
INFO="93m"     # Info message
LINK="95m"     # Share Link Message
#############################

blue(){
    echo -e "\033[34m\033[01m$1\033[0m"
}
green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}
bred(){
    echo -e "\033[31m\033[01m\033[05m$1\033[0m"
}
byellow(){
    echo -e "\033[33m\033[01m\033[05m$1\033[0m"
}


####################################
colorEcho(){
    COLOR=$1
    echo -e "\033[${COLOR}${@:2}\033[0m"
}
#########域名解析验证###################
isresolved(){
    if [ $# = 2 ]
    then
        myip=$2
    else
        myip=`curl --silent http://dynamicdns.park-your-domain.com/getip`
    fi
    ips=(`nslookup $1 1.1.1.1 | grep -v 1.1.1.1 | grep Address | cut -d " " -f 2`)
    for ip in "${ips[@]}"
    do
        if [ $ip == $myip ]
        then
            return 0
        else
            continue
        fi
    done
    return 1
}
###############安装输入选项################
userinput(){
green  " ============================================================================"
yellow " 请输入域名(每个域名每周只能使用5次，安装失败也算次数，可以换不同的域名解决）"
green  " ============================================================================"
read domain
  if [[ -z "$domain" ]]; then
    green  " =========================================================================================="
	yellow " 域名不能为空，请重新输入(每个域名每周只能使用5次，安装失败也算次数，可以换不同的域名解决）"
	green  " =========================================================================================="
    read domain
  fi
green  " ========================================="
yellow " 请输入密码(这个是配置trojan的密码，牢记）"
green  " ========================================="
read passwordd
  if [[ -z "$passwordd" ]]; then
	green  " ======================================================="
	yellow " 密码不能为空，请重新输入(这个是配置trojan的密码，牢记）"
	green  " ========================================================"
    read passwordd
  fi
}
###############linux系统检查####################
osdist(){

set -e
 if cat /etc/*release | grep ^NAME | grep Debian; then
    green  " ======================="
	yellow " linux系统检查通过"
	green  " ======================="
    dist=debian
 else
    green  " ======================="
	red " 只能在debian>=9以上安装"
	green  " ======================="
    exit 1;
 fi
}
###############更新系统list################
updatesystem(){
  apt-get update -qq
}
##############更新软件包########
upgradesystem(){
  if [[ $dist = debian ]]; then
    export DEBIAN_FRONTEND=noninteractive 
    apt-get upgrade -q -y
    apt-get autoremove -qq -y > /dev/null
 else
  clear
    green  " =============="
	red " 软件包更新错误"
	green  " =============="
    exit 1;
 fi
}
#########打开防火墙端口########################
openfirewall(){
  iptables -I INPUT -p tcp -m tcp --dport 443 -j ACCEPT
  iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT
  iptables -I OUTPUT -j ACCEPT
}
##########安装依赖包#############
installdependency(){
  green  " ========================="
  yellow " 开始安装trojan nginx acme"
  green  " ========================="
  if [[ $dist = debian ]]; then
    apt-get install sudo curl socat xz-utils wget apt-transport-https gnupg gnupg2 dnsutils lsb-release python-pil unzip resolvconf -qq -y
    if [[ $(lsb_release -cs) == jessie ]]; then
	  green  " ==================================="
	  yellow " debian8系统不支持python3-qrcode跳过"
	  green  " ==================================="
      else
        apt-get install python3-qrcode -qq -y
    fi
 else
  clear
    green  " =============="
	red " 依赖包安装错误"
	green  " =============="
    exit 1;
 fi
}
###从官方源开始安装trojan####
installtrojan-gfw(){
  bash -c "$(wget -O- https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"
}

##########安装nginx################
nginxapt(){
  wget https://nginx.org/keys/nginx_signing.key -q
  apt-key add nginx_signing.key
  rm -rf nginx_signing.key
  touch /etc/apt/sources.list.d/nginx.list
  cat > '/etc/apt/sources.list.d/nginx.list' << EOF
deb https://nginx.org/packages/mainline/debian/ $(lsb_release -cs) nginx
deb-src https://nginx.org/packages/mainline/debian/ $(lsb_release -cs) nginx
EOF
  apt-get remove nginx-common -qq -y
  apt-get update -qq
  apt-get install nginx -q -y
}

############安装nginx########################
installnginx(){
  if [[ $dist = debian ]]; then
    nginxapt
 else
  clear
    green  " =============="
	red " 安装nginx错误"
	green  " =============="
    exit 1;
 fi
}
#############安装acme#####################
installacme(){
  curl -s https://get.acme.sh | sh
  sudo ~/.acme.sh/acme.sh --upgrade --auto-upgrade > /dev/null
  rm -rf /etc/trojan/
  mkdir /etc/trojan/
}
##################################################
issuecert(){
  rm -rf /etc/nginx/sites-enabled/*
  rm -rf /etc/nginx/sites-available/*
  rm -rf /etc/nginx/conf.d/*
  touch /etc/nginx/conf.d/default.conf
    cat > '/etc/nginx/conf.d/default.conf' << EOF
server {
    listen       80;
    server_name  $domain;
    #charset koi8-r;
    #access_log  /var/log/nginx/host.access.log  main;
    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }
    #error_page  404              /404.html;
    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
    # proxy the PHP scripts to Apache listening on 127.0.0.1:80
    #
    #location ~ \.php$ {
    #    proxy_pass   http://127.0.0.1;
    #}
    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    #location ~ \.php$ {
    #    root           html;
    #    fastcgi_pass   127.0.0.1:9000;
    #    fastcgi_index  index.php;
    #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
    #    include        fastcgi_params;
    #}
    # deny access to .htaccess files, if Apache's document root
    # concurs with nginx's one
    #
    #location ~ /\.ht {
    #    deny  all;
    #}
}
EOF
  wget https://raw.githubusercontent.com/pzwsquare/trojan/master/web.zip
    unzip web.zip
  rm -rf /usr/share/nginx/html/*
  mv ./index.html /usr/share/nginx/html/
  rm -rf web.zip
  systemctl start nginx
  sudo ~/.acme.sh/acme.sh --issue --nginx -d $domain -k ec-256 --force --log
}
##################################################
renewcert(){
  sudo ~/.acme.sh/acme.sh --issue --nginx -d $domain -k ec-256 --force --log
}
##################################################
installcert(){
  sudo ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/trojan/trojan.crt --keypath /etc/trojan/trojan.key --ecc
}
##################################################
installkey(){
  chmod +r /etc/trojan/trojan.key
}
##################################################
changepasswd(){
  openssl dhparam -out /etc/trojan/trojan.pem 2048
  cat > '/usr/local/etc/trojan/config.json' << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "passwordd"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/etc/trojan/trojan.crt",
        "key": "/etc/trojan/trojan.key",
        "key_password": "",
        "cipher": "TLS_AES_128_GCM_SHA256",
	"cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": true,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": true,
        "no_delay": true,
        "keep_alive": true,
        "fast_open": true,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF
  sed  -i "s/passwordd/$passwordd/g" /usr/local/etc/trojan/config.json
}
########在nginx配置trojan##############
nginxtrojan(){
rm -rf /etc/nginx/sites-available/*
rm -rf /etc/nginx/sites-enabled/*
rm -rf /etc/nginx/conf.d/*
touch /etc/nginx/conf.d/trojan.conf
  cat > '/etc/nginx/conf.d/trojan.conf' << EOF
server {
  listen 127.0.0.1:80;
    server_name $domain;
    location / {
      root /usr/share/nginx/html/;
        index index.html;
        }
  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
server {
    listen 80;
    listen [::]:80;
    server_name $domain;
    return 301 https://$domain;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
EOF
nginx -s reload
}

##########启动trojan&nginx###############
autostart(){
  systemctl start trojan
  systemctl enable nginx
  systemctl enable trojan
}
##########安装bbr#####################
tcp-bbr(){
  cat > '/etc/sysctl.d/99-sysctl.conf' << EOF
#
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables.
# See sysctl.conf (5) for information.
#
#kernel.domainname = example.com
# Uncomment the following to stop low-level messages on console
#kernel.printk = 3 4 1 3
##############################################################3
# Functions previously found in netbase
#
# Uncomment the next two lines to enable Spoof protection (reverse-path filter)
# Turn on Source Address Verification in all interfaces to
# prevent some spoofing attacks
#net.ipv4.conf.default.rp_filter=1
#net.ipv4.conf.all.rp_filter=1
# Uncomment the next line to enable TCP/IP SYN cookies
# See http://lwn.net/Articles/277146/
# Note: This may impact IPv6 TCP sessions too
#net.ipv4.tcp_syncookies=1
# Uncomment the next line to enable packet forwarding for IPv4
#net.ipv4.ip_forward=1
# Uncomment the next line to enable packet forwarding for IPv6
#  Enabling this option disables Stateless Address Autoconfiguration
#  based on Router Advertisements for this host
#net.ipv6.conf.all.forwarding=1
###################################################################
# Additional settings - these settings can improve the network
# security of the host and prevent against some network attacks
# including spoofing attacks and man in the middle attacks through
# redirection. Some network environments, however, require that these
# settings are disabled so review and enable them as needed.
#
# Do not accept ICMP redirects (prevent MITM attacks)
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv6.conf.all.accept_redirects = 0
# _or_
# Accept ICMP redirects only for gateways listed in our default
# gateway list (enabled by default)
# net.ipv4.conf.all.secure_redirects = 1
#
# Do not send ICMP redirects (we are not a router)
#net.ipv4.conf.all.send_redirects = 0
#
# Do not accept IP source route packets (we are not a router)
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv6.conf.all.accept_source_route = 0
#
# Log Martian Packets
#net.ipv4.conf.all.log_martians = 1
#
###################################################################
# Magic system request Key
# 0=disable, 1=enable all
# Debian kernels have this set to 0 (disable the key)
# See https://www.kernel.org/doc/Documentation/sysrq.txt
# for what other values do
#kernel.sysrq=1
###################################################################
# Protected links
#
# Protects against creating or following links under certain conditions
# Debian kernels have both set to 1 (restricted) 
# See https://www.kernel.org/doc/Documentation/sysctl/fs.txt
#fs.protected_hardlinks=0
#fs.protected_symlinks=0
# Overrule forwarding behavior. Accept Router Advertisements
net.ipv6.conf.all.accept_ra = 2
# max open files
fs.file-max = 51200
# max read buffer
net.core.rmem_max = 67108864
# max write buffer
net.core.wmem_max = 67108864
# default read buffer
net.core.rmem_default = 65536
# default write buffer
net.core.wmem_default = 65536
# max processor input queue
net.core.netdev_max_backlog = 4096
# max backlog
net.core.somaxconn = 4096
# resist SYN flood attacks
net.ipv4.tcp_syncookies = 1
# reuse timewait sockets when safe
net.ipv4.tcp_tw_reuse = 1
# short FIN timeout
net.ipv4.tcp_fin_timeout = 30
# short keepalive time
net.ipv4.tcp_keepalive_time = 1200
# outbound port range
net.ipv4.ip_local_port_range = 10000 65000
# max timewait sockets held by system simultaneously
net.ipv4.tcp_max_tw_buckets = 5000
# turn on TCP Fast Open on both client and server side
net.ipv4.tcp_fastopen = 3
# TCP receive buffer
net.ipv4.tcp_rmem = 4096 87380 67108864
# TCP write buffer
net.ipv4.tcp_wmem = 4096 65536 67108864
# turn on path MTU discovery
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_max_syn_backlog = 12800
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl -p
    cat > '/etc/systemd/system.conf' << EOF
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
# Entries in this file show the compile time defaults.
# You can change settings by editing this file.
# Defaults can be restored by simply deleting this file.
#
# See systemd-system.conf(5) for details.
[Manager]
#LogLevel=info
#LogTarget=journal-or-kmsg
#LogColor=yes
#LogLocation=no
#DumpCore=yes
#ShowStatus=yes
#CrashChangeVT=no
#CrashShell=no
#CrashReboot=no
#CtrlAltDelBurstAction=reboot-force
#CPUAffinity=1 2
#RuntimeWatchdogSec=0
#ShutdownWatchdogSec=10min
#WatchdogDevice=
#CapabilityBoundingSet=
#NoNewPrivileges=no
#SystemCallArchitectures=
#TimerSlackNSec=
#DefaultTimerAccuracySec=1min
#DefaultStandardOutput=journal
#DefaultStandardError=inherit
#DefaultTimeoutStartSec=90s
DefaultTimeoutStopSec=30s
#DefaultRestartSec=100ms
#DefaultStartLimitIntervalSec=10s
#DefaultStartLimitBurst=5
#DefaultEnvironment=
#DefaultCPUAccounting=no
#DefaultIOAccounting=no
#DefaultIPAccounting=no
#DefaultBlockIOAccounting=no
#DefaultMemoryAccounting=yes
#DefaultTasksAccounting=yes
#DefaultTasksMax=
#DefaultLimitCPU=
#DefaultLimitFSIZE=
#DefaultLimitDATA=
#DefaultLimitSTACK=
#DefaultLimitCORE=
#DefaultLimitRSS=
#DefaultLimitNOFILE=1024:524288
#DefaultLimitAS=
#DefaultLimitNPROC=
#DefaultLimitMEMLOCK=
#DefaultLimitLOCKS=
#DefaultLimitSIGPENDING=
#DefaultLimitMSGQUEUE=
#DefaultLimitNICE=
#DefaultLimitRTPRIO=
#DefaultLimitRTTIME=
DefaultLimitCORE=infinity
DefaultLimitNOFILE=51200
DefaultLimitNPROC=51200
EOF
    cat > '/etc/security/limits.conf' << EOF
# /etc/security/limits.conf
#
#Each line describes a limit for a user in the form:
#
#<domain>        <type>  <item>  <value>
#
#Where:
#<domain> can be:
#        - a user name
#        - a group name, with @group syntax
#        - the wildcard *, for default entry
#        - the wildcard %, can be also used with %group syntax,
#                 for maxlogin limit
#        - NOTE: group and wildcard limits are not applied to root.
#          To apply a limit to the root user, <domain> must be
#          the literal username root.
#
#<type> can have the two values:
#        - "soft" for enforcing the soft limits
#        - "hard" for enforcing hard limits
#
#<item> can be one of the following:
#        - core - limits the core file size (KB)
#        - data - max data size (KB)
#        - fsize - maximum filesize (KB)
#        - memlock - max locked-in-memory address space (KB)
#        - nofile - max number of open file descriptors
#        - rss - max resident set size (KB)
#        - stack - max stack size (KB)
#        - cpu - max CPU time (MIN)
#        - nproc - max number of processes
#        - as - address space limit (KB)
#        - maxlogins - max number of logins for this user
#        - maxsyslogins - max number of logins on the system
#        - priority - the priority to run user process with
#        - locks - max number of file locks the user can hold
#        - sigpending - max number of pending signals
#        - msgqueue - max memory used by POSIX message queues (bytes)
#        - nice - max nice priority allowed to raise to values: [-20, 19]
#        - rtprio - max realtime priority
#        - chroot - change root to directory (Debian-specific)
#
#<domain>      <type>  <item>         <value>
#
#*               soft    core            0
#root            hard    core            100000
#*               hard    rss             10000
#@student        hard    nproc           20
#@faculty        soft    nproc           20
#@faculty        hard    nproc           50
#ftp             hard    nproc           0
#ftp             -       chroot          /ftp
#@student        -       maxlogins       4
# End of file
* soft nofile 51200
* hard nofile 51200
EOF
    cat > '/etc/profile' << EOF
# /etc/profile: system-wide .profile file for the Bourne shell (sh(1))
# and Bourne compatible shells (bash(1), ksh(1), ash(1), ...).
if [ "${PS1-}" ]; then
  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then
    # The file bash.bashrc already sets the default PS1.
    # PS1='\h:\w\$ '
    if [ -f /etc/bash.bashrc ]; then
      . /etc/bash.bashrc
    fi
  else
    if [ "`id -u`" -eq 0 ]; then
      PS1='# '
    else
      PS1='$ '
    fi
  fi
fi
if [ -d /etc/profile.d ]; then
  for i in /etc/profile.d/*.sh; do
    if [ -r $i ]; then
      . $i
    fi
  done
  unset i
fi
ulimit -SHn 51200
EOF
systemctl daemon-reload
}
##########安装iptables-persistent########
iptables-persistent(){
  if [[ $dist = debian ]]; then
    export DEBIAN_FRONTEND=noninteractive 
    apt-get install iptables-persistent -q -y > /dev/null
 else
  clear
	green  " ==========================="
	red " 安装iptables-persistent错误"
	green  " ==========================="
    exit 1;
 fi
}
############安装DNSMASQ#################
dnsmasq(){
    if [[ $dist = debian ]]; then
    export DEBIAN_FRONTEND=noninteractive 
    apt-get install dnsmasq -q -y > /dev/null
 else
  clear
    green  " ==============="
	red " 安装dnsmasq错误"
	green  " ==============="
    exit 1;
 fi
 mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
 touch /etc/dnsmasq.conf
     cat > '/etc/dnsmasq.conf' << EOF
port=53
domain-needed
bogus-priv
no-resolv
server=8.8.4.4#53
server=1.1.1.1#53
interface=lo
bind-interfaces
listen-address=127.0.0.1
cache-size=10000
no-negcache
log-queries 
log-facility=/var/log/dnsmasq.log 
EOF
echo "nameserver 127.0.0.1" > '/etc/resolv.conf'
systemctl restart dnsmasq
systemctl enable dnsmasq
}

##########卸载Trojan-Gfw##########
removetrojan(){
  systemctl stop trojan
  systemctl disable trojan
  rm -rf /usr/local/etc/trojan/*
  rm -rf /etc/trojan/*
  rm -rf /etc/systemd/system/trojan.service
  rm -rf ~/.acme.sh/$domain
}

###########卸载Nginx dnsmasq and acme###############
removenginx(){
  systemctl stop nginx
  systemctl disable nginx
  apt purge nginx -p -y
  apt purge dnsmasq -p -y
  rm -rf /etc/apt/sources.list.d/nginx.list
  sudo ~/.acme.sh/acme.sh --uninstall
}
##########检查更新trojan############
checkupdate(){
  cd
  wget https://install.direct/go.sh -q
  sudo bash go.sh --check
  rm go.sh
  bash -c "$(wget -O- https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"
}


DELAY=3 

while true; do
  clear
  green " ========================================================================"
  green " 简介：debian一键安装trojan"
  green " 系统：>=debian9"
  green " Youtube：米月"
  green " 电报群：https://t.me/mi_yue"
  green " Youtube频道地址：https://www.youtube.com/channel/UCr4HCEgaZ0cN5_7tLHS_xAg"
  green " ========================================================================"
  echo
  green  " 1. 一键安装trojan"
  green  " 2. 一键更新trojan"
  red    " 3. 一键卸载trojan"
  yellow " 0. 退出安装trojan"
  echo

  read -p "请输入数字[0-3] > "

  if [[ $REPLY =~ ^[0-3]$ ]]; then
    case $REPLY in
      1)
        userinput
        osdist
        updatesystem
        green  " ==============="
		yellow " 开始安装dnsmasq"
		green  " ==============="
        dnsmasq
        green  " =================="
		yellow " 开始更新系统软件包"
		green  " =================="
        upgradesystem
        green  " =============="
		yellow " 开始安装依赖包"
		green  " =============="
        installdependency
        if isresolved $domain
        then
        :
        else 
		green  " =========================="
		red " 请检查域名和vps的地址是否一致"
		green  " =========================="
        exit -1
        clear
        fi
        green  " =============="
		yellow " 打开防火墙端口"
		green  " =============="
        openfirewall
        green  " =============="
		yellow " 开始安装trojan"
		green  " =============="
        installtrojan-gfw
        green  " ============="
		yellow " 开始安装nginx"
		green  " ============="
        installnginx
        green  " ============"
		yellow " 开始安装acme"
		green  " ============"
        installacme
        green  " ============"
		yellow " 开始申请证书"
		green  " ============"
        issuecert
        green  " ==================="
		yellow " 开始nginx配置trojan"
		green  " ==================="
        nginxtrojan
        green  " ================"
		yellow " 开始安装安装证书"
		green  " ================"
        installcert
        green  " ============"
		yellow " 开始配置证书"
		green  " ============"
        installkey
        green  " =============="
		yellow " 开始配置trojan"
		green  " =============="
        changepasswd
        green  " ======================"
		yellow " 设置自启动trojan nginx"
		green  " ======================"
        autostart
		green  " ==========================="
		yellow " 开始安装iptables-persistent"
		green  " ==========================="
        iptables-persistent  
        green  " ==========================="
		yellow " 开始安装bbr"
		green  " ==========================="
        tcp-bbr
		green " ========================================================================="
		green " 简介：debian一键安装trojan"
		green " 系统：>=debian9"
		green " Youtube：米月"
		green " 电报群：https://t.me/mi_yue"
		green " Youtube频道地址：https://www.youtube.com/channel/UCr4HCEgaZ0cN5_7tLHS_xAg"
		green " ========================================================================="
		green " Trojan已安装完成，复制下面的信息，在OP里进行配置"
		red   " 服务器地址：$domain"
		red   " 服务器端口：443"
		red   " 服务器密码：$passwordd"
		red   " 忘记密码修改文件：/usr/local/etc/trojan/config.json"
		green " ========================================================================="
        break
        ;;
      2)
        checkupdate
        break
        ;;
      3)
        removetrojan
        removenginx
        green  " =============="
		yellow " 卸载trojan完成"
		green  " =============="
        break
        ;;          
      0)
        break
        ;;
    esac
  else
    green  " ============================"
	red " 输入的数字不正确，请重新输入"
	green  " ============================"
    sleep $DELAY
  fi
done
