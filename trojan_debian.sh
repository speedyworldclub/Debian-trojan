#!/bin/bash


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


function install_trojan(){
systemctl stop firewalld
systemctl disable firewalld

apt -y install dnsutils wget unzip zip curl tar
green "======================="
yellow "请输入域名(每个域名每周只能使用5次，安装失败也算次数，可以换不同的域名解决）"
green "======================="
read your_domain
real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
local_addr=`curl ipv4.icanhazip.com`
if [ $real_addr == $local_addr ] ; then
	green "=========================================="
	green "域名正常解析，开始安装nginx并申请证书"
	green "=========================================="
	sleep 1s
	apt install -y nginx
	systemctl enable nginx.service
	#设置伪装站点
	rm -rf /var/www/html/*
	cd /var/www/html/
	wget https://raw.githubusercontent.com/pzwsquare/trojan-wiz/master/web.zip
    	unzip web.zip
	systemctl start nginx.service
	#申请证书
	mkdir /usr/src/trojan-cert
	curl https://get.acme.sh | sh
	~/.acme.sh/acme.sh  --issue --debug -d $your_domain  --webroot /var/www/html/
    	~/.acme.sh/acme.sh  --installcert  -d  $your_domain   \
        --key-file   /usr/src/trojan-cert/private.key \
        --fullchain-file /usr/src/trojan-cert/fullchain.cer \
        --reloadcmd  "systemctl force-reload  nginx.service"
	if test -s /usr/src/trojan-cert/fullchain.cer; then
        cd /usr/src
	wget https://github.com/trojan-gfw/trojan/releases/download/v1.13.0/trojan-1.13.0-linux-amd64.tar.xz
	tar xf trojan-1.*
	trojan_passwd=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
	
	rm -rf /usr/src/trojan/server.conf
	cat > /usr/src/trojan/server.conf <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$trojan_passwd"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/usr/src/trojan-cert/fullchain.cer",
        "key": "/usr/src/trojan-cert/private.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
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

	#增加启动脚本
	
	cat > /etc/systemd/system/trojan.service <<-EOF
[Unit]
Description=trojan
After=network.target

[Service]
ExecStart=/usr/src/trojan/trojan -c "/usr/src/trojan/server.conf"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

	chmod +x /etc/systemd/system/trojan.service
	systemctl start trojan
	systemctl enable trojan
	green "========================================================================="
	green "简介：debian一键安装trojan"
    green "系统：>=debian9"
    green "Youtube：米月"
    green "电报群：https://t.me/mi_yue"
    green "Youtube频道地址：https://www.youtube.com/channel/UCr4HCEgaZ0cN5_7tLHS_xAg"
	green "========================================================================="
	green "Trojan已安装完成，复制下面的信息，在OP里进行配置"
	red   "服务器地址：${your_domain}"
	red   "服务器端口：443"
	red   "服务器密码：${trojan_passwd}"
	red   "忘记密码修改文件：/usr/src/trojan/server.conf"
	green "========================================================================="
	else
    red "================================"
	red "证书申请失败，trojan安装失败"
	red "================================"
	fi
	
else
	red "================================"
	red "域名地址解析与VPS IP地址不一致"
	red "安装失败，请确保域名正常解析"
	red "================================"
fi
}

function remove_trojan(){
    red "================================"
    red "开始卸载trojan"
    red "开始卸载nginx"
    red "================================"
    systemctl stop trojan
    systemctl disable trojan
    rm -f /etc/systemd/system/trojan.service
    yum remove -y nginx
    rm -rf /usr/src/trojan*
    rm -rf /var/www/html/*
    green "=============="
    green "trojan卸载完成"
	green "nginx卸载完成"
    green "=============="
}

function bbr(){
    red "================================"
    red "开始安装BBR"
    red "================================"
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	sysctl -p
    green "=============="
    green "BBR安装完毕"
    green "=============="
}

start_menu(){
    clear
    green " ========================================================================"
    green "简介：debian一键安装trojan"
    green "系统：>=debian9"
    green "Youtube：米月"
    green "电报群：https://t.me/mi_yue"
    green "Youtube频道地址：https://www.youtube.com/channel/UCr4HCEgaZ0cN5_7tLHS_xAg"
    green " ========================================================================"
    echo
    green  " 1. 一键安装trojan"
    red    " 2. 卸载trojan"
	green  " 3. 一键安装BBR"
    yellow " 0. 退出脚本"
    echo
    read -p "请输入数字:" num
    case "$num" in
    1)
    install_trojan
    ;;
    2)
    remove_trojan 
    ;;
	3)
    bbr 
    ;;
    0)
    exit 1
    ;;
    *)
    clear
    red "输入的数字不正确，请重新输入"
    sleep 1s
    start_menu
    ;;
    esac
}

start_menu