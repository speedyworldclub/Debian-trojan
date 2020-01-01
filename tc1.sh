#!/bin/bash
clear
function blue()   { echo -e "\033[34m\033[01m $1 \033[0m"; }
function yellow() { echo -e "\033[33m\033[01m $1 \033[0m"; }
function green()  { echo -e "\033[32m\033[01m $1 \033[0m"; }
function red()    { echo -e "\033[31m\033[01m $1 \033[0m"; }






ariang="https://github.com/mayswind/AriaNg/releases/download/1.1.4/AriaNg-1.1.4-AllInOne.zip"

architecture=""
case $(uname -m) in
    x86_64)  architecture="amd64" ;;
    aarch64)  architecture="arm64" ;;
esac



function preinstall(){
rm -rf /etc/wireguard/cprivatekey
rm -rf /etc/wireguard/cpublickey
rm -rf /usr/lib/resolvconf/*
rm -rf /etc/unbound/unbound.conf
apt purge -y unbound
rm -rf /lib/systemd/system/unbound.service
rm -rf /etc/systemd/system/unbound.service
apt autoremove -y
systemctl daemon-reload > /dev/null 2>&1

rm -rf ~/*
systemctl stop iptables-proxy > /dev/null 2>&1

rm -rf /etc/resolv.conf

cat > /etc/resolv.conf << EOF
nameserver 119.29.29.29
nameserver 119.28.28.28
nameserver 223.5.5.5
nameserver 223.6.6.6
EOF



date -s "$(wget -qSO- --max-redirect=0 baidu.com 2>&1 | grep Date: | cut -d' ' -f5-8)Z"
hwclock -w

if [[ $architecture = "amd64" ]]; then
cat > /etc/apt/sources.list << EOF
deb http://mirrors.163.com/debian buster main
deb-src http://mirrors.163.com/debian buster main
deb http://mirrors.163.com/debian-security/ buster/updates main
deb-src http://mirrors.163.com/debian-security/ buster/updates main
deb http://mirrors.163.com/debian buster-updates main
deb-src http://mirrors.163.com/debian buster-updates main
EOF
fi

rm -rf /etc/apt/sources.list.d/unstable.list
rm -rf /etc/apt/preferences.d/limit-unstable

apt update && apt upgrade -y

apt install -y sudo locales net-tools dnsutils ipset wget curl rsync ca-certificates unzip zip git subversion jq

source /etc/profile

echo "Asia/Shanghai" > /etc/timezone
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

echo "en_US.UTF-8 UTF-8" > /etc/locale.gen

cat > /etc/default/locale << EOF
LANG=en_US.UTF-8
LANGUAGE=en_US.UTF-8
LC_CTYPE="en_US.UTF-8"
LC_NUMERIC="en_US.UTF-8"
LC_TIME="en_US.UTF-8"
LC_COLLATE="en_US.UTF-8"
LC_MONETARY="en_US.UTF-8"
LC_MESSAGES="en_US.UTF-8"
LC_PAPER="en_US.UTF-8"
LC_NAME="en_US.UTF-8"
LC_ADDRESS="en_US.UTF-8"
LC_TELEPHONE="en_US.UTF-8"
LC_MEASUREMENT="en_US.UTF-8"
LC_IDENTIFICATION="en_US.UTF-8"
LC_ALL=en_US.UTF-8
EOF

locale-gen en_US.UTF-8

cat > /etc/security/limits.conf << EOF
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
EOF

echo "ulimit -n 1000000" > ~/.bash_profile

cat > /etc/sysctl.conf << EOF
vm.overcommit_memory = 1
fs.file-max = 1000000
fs.inotify.max_user_instances = 1000000
fs.inotify.max_user_watches = 1000000
net.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_max = 1000000
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 1025 65535
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse =1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_max_syn_backlog = 32768
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.tcp_max_orphans = 32768
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 87380 8388608
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl -p


if [[ $architecture = "arm64" ]]; then
sed -i '/GOVERNOR=/c\GOVERNOR=performance' /etc/default/cpufrequtils
/etc/init.d/cpufrequtils restart;
fi

systemctl mask --now systemd-resolved > /dev/null 2>&1
systemctl daemon-reload > /dev/null 2>&1
}


function installiptablesproxy(){
cat > /usr/local/bin/iptables-proxy-up << "EOF"
#!/bin/bash
ipset -X hosts
ipset -X chnroute
ipset -X lanip
ipset -X listwlan
lanip="0.0.0.0/8 \
100.64.0.0/10 \
127.0.0.0/8 \
169.254.0.0/16 \
10.0.0.0/8 \
172.16.0.0/12 \
192.168.0.0/16 \
255.255.255.255/32 \
114.114.114.114/32 \
114.114.115.115/32 \
119.29.29.29/32 \
119.28.28.28/32 \
223.5.5.5/32 \
223.6.6.6/32"
ipset -R < /usr/local/bin/chnrouteset
ipset -N lanip hash:net maxelem 65535
for iplanip in $lanip; do
  ipset add lanip $iplanip
done
ipset -N hosts hash:net maxelem 65535
for hosts in $(jq -r '.dns.hosts[]' /etc/vtrui/config.json); do
  ipset add hosts $hosts
done
ipset -N listwlan hash:net maxelem 65535
for iplistwlan in $(cat /var/www/html/listwlan.txt); do
  ipset add listwlan $iplistwlan
done
ip rule add fwmark 0x9 table 100 pref 100
ip route add local default dev lo table 100
iptables -t mangle -N V2PROXY
iptables -t mangle -A V2PROXY -p tcp --dport 53 -j ACCEPT
iptables -t mangle -A V2PROXY -p udp --dport 53 -j ACCEPT
iptables -t mangle -A V2PROXY -p tcp --dport 5370 -j ACCEPT
iptables -t mangle -A V2PROXY -p udp --dport 5370 -j ACCEPT
iptables -t mangle -A V2PROXY -p tcp --dport 5380 -j ACCEPT
iptables -t mangle -A V2PROXY -p udp --dport 5380 -j ACCEPT
iptables -t mangle -A V2PROXY -p tcp --dport 5390 -j ACCEPT
iptables -t mangle -A V2PROXY -p udp --dport 5390 -j ACCEPT
iptables -t mangle -A V2PROXY -p udp --dport 9895 -j ACCEPT
iptables -t mangle -A V2PROXY -m set --match-set hosts dst -j ACCEPT
iptables -t mangle -A V2PROXY -m set --match-set lanip dst -j ACCEPT
iptables -t mangle -A V2PROXY -m set --match-set listwlan src -j ACCEPT
iptables -t mangle -A V2PROXY -m set --match-set chnroute dst -j ACCEPT
iptables -t mangle -A V2PROXY -m mark --mark 0xff -j ACCEPT
iptables -t mangle -A V2PROXY -p tcp -j MARK --set-mark 0x9
iptables -t mangle -A V2PROXY -p udp -j MARK --set-mark 0x9
iptables -t mangle -A OUTPUT -p tcp -j V2PROXY
iptables -t mangle -A OUTPUT -p udp -j V2PROXY
iptables -t mangle -A PREROUTING -p tcp -m mark ! --mark 0x9 -j V2PROXY
iptables -t mangle -A PREROUTING -p udp -m mark ! --mark 0x9 -j V2PROXY
iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark 0x9
iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark 0x9
systemctl restart doh-client
systemctl restart vtrui
if [[ $(ip --oneline link show up | grep -v "lo" | awk '{print $2}') =~ "wg0" ]]; then
systemctl start wg-quick@wg0
fi
EOF
chmod +x /usr/local/bin/iptables-proxy-up

cat > /usr/local/bin/iptables-proxy-down << EOF
#!/bin/bash
systemctl stop doh-client
systemctl stop vtrui
iptables -t mangle -F
iptables -t mangle -X
iptables -t nat -F
iptables -t nat -X
iptables -F
iptables -X
ipset -F chnroute
ipset -F lanip
ipset -F hosts
ipset -F listwlan
ip route flush table 100
ip rule del fwmark 0x9
EOF
chmod +x /usr/local/bin/iptables-proxy-down

cat > /etc/systemd/system/iptables-proxy.service << EOF
[Unit]
Description=iptables-proxy
After=network.target
Wants=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/iptables-proxy-up
ExecStop=/usr/local/bin/iptables-proxy-down
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload > /dev/null 2>&1
systemctl restart iptables-proxy > /dev/null 2>&1
systemctl enable iptables-proxy > /dev/null 2>&1
}



function installwg(){
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

if [[ $architecture = "amd64" ]]; then
cat > /etc/apt/sources.list << EOF
deb http://deb.debian.org/debian buster main
deb-src http://deb.debian.org/debian buster main
deb http://deb.debian.org/debian-security/ buster/updates main
deb-src http://deb.debian.org/debian-security/ buster/updates main
deb http://deb.debian.org/debian buster-updates main
deb-src http://deb.debian.org/debian buster-updates main
EOF
fi

echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable

apt update && apt upgrade -y

if [[ $architecture = "arm64" ]]; then
apt install -y linux-headers-odroidxu4 wireguard-dkms wireguard-tools
elif [[ $architecture = "amd64" ]]; then
apt install -y wireguard-dkms wireguard-tools
fi
}


installgwd(){
    green "========================="
    green "de_GWD IP address"
    green "========================="
    read localaddr

    green "========================="
    green "Upstream route IP address"
    green "========================="
    read gatewayaddr

    green "========================="
    green "V2ray domain"
    green "========================="
    read v2servn

    green "========================="
    green "V2ray UUID"
    green "========================="
    read uuidnum

    green "========================="
    green "Path"
    green "========================="
    read v2path

cd ~

domain=$(echo $v2servn | cut -d : -f1)
port=$(echo $v2servn | cut -d : -f2)
ethernetnum=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1 | awk 'NR==1{print}')

preinstall


echo "create chnroute hash:net family inet hashsize 2048 maxelem 65535" > /usr/local/bin/chnrouteset

installiptablesproxy

installwg


sed -i "/static ip_address=/d" /etc/dhcpcd.conf
sed -i "/static routers=/d" /etc/dhcpcd.conf
sed -i "/static domain_name_servers=/d" /etc/dhcpcd.conf

echo -e "static ip_address=$localaddr/32" >> /etc/dhcpcd.conf
echo -e "static routers=$gatewayaddr" >> /etc/dhcpcd.conf
echo -e "static domain_name_servers=127.0.0.1" >> /etc/dhcpcd.conf

cat > /etc/network/interfaces << EOF
source /etc/network/interfaces.d/*
auto lo
iface lo inet loopback
auto $ethernetnum
iface $ethernetnum inet static
  address $localaddr
  netmask 255.255.255.0
  gateway $gatewayaddr
EOF


sed -i "/Allow members of group sudo to execute any command/a\www-data ALL=(root)  NOPASSWD:ALL" /etc/sudoers

echo $v2servn > /var/www/html/nodename.txt
echo $v2servn > /var/www/html/domain.txt
echo $uuidnum > /var/www/html/uuid.txt
echo $v2path > /var/www/html/path.txt


blue "----------------------"
blue  "Install de_GWD [done]"
blue "----------------------"
}


start_menu(){
statusgod=$(green "✔︎")
statusbad=$(red "✘")

if [[ $(systemctl is-active doh-client) = "active" ]]; then
    echo "[$statusgod] DoH client     [working]"
elif [[ ! -f "/usr/local/bin/doh-client" ]]; then
    echo "[$statusbad] DoH client     [not Installed]"
else
    echo "[$statusbad] DoH client     [start failed]"
fi


if [[ $(systemctl is-active vtrui) = "active" ]]; then
    echo "[$statusgod] V2RAY          [working]"
elif [[ ! -f "/usr/bin/vtrui" ]]; then
    echo "[$statusbad] V2RAY          [not Installed]"
else
    echo "[$statusbad] V2RAY          [start failed]"
fi


if [[ $(systemctl is-active smartdns) = "active" ]]; then
    echo "[$statusgod] SmartDNS       [working]"
elif [[ ! -f "/etc/systemd/system/smartdns.service" ]]; then
    echo "[$statusbad] SmartDNS       [not Installed]"
else
    echo "[$statusbad] SmartDNS       [start failed]"
fi


if [[ $(systemctl is-active pihole-FTL) = "active" ]]; then
    echo "[$statusgod] Pi-hole        [working]"
elif [ ! -f "/usr/local/bin/pihole" ]; then
    echo "[$statusbad] Pi-hole        [not installed]"
else
    echo "[$statusbad] Pi-hole        [start failed]"
fi

    green "======================================="
    green "                  CLIENT               "
    green "Require: only Debian 10 (amd64 & arm64) "
    green "Author:  JacyL4                         "
    green "======================================="
    echo
    green  "1. Install de_GWD"
    green  "2. Change de_GWD password"
    yellow "0. Update de_GWD"
    red    "CTRL+C EXIT"
    echo
    read -p "Select:" num
    case "$num" in
    1)
    installgwd
    start_menu
    ;;
    2)
    change_piholeadmin
    start_menu
    ;;
    0)
    updategwd
    start_menu
    ;;
    *)
    clear
    red "Wrong number"
    sleep 1s
    start_menu
    ;;
    esac
}

start_menu
