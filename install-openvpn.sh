#!/bin/sh
# Author:	DjRakso
# Date:		November 4th, 2020



### FILES & DIRECTORIES ###
# /dev.
DEV_DIR=/dev
# /dev/net.
DEV_NET_DIR=$DEV_DIR/net
# /dev/net/tun.
DEV_NET_TUN_FILE=$DEV_NET_DIR/tun
# /etc.
ETC_DIR=/etc
ETC_SYSTEM_CONFIGURATION_FILE=$ETC_DIR/sysctl.conf
# /etc/openvpn.
ETC_OPENVPN_DIR=$ETC_DIR/openvpn
ETC_OPENVPN_SERVER_CONF_FILE=$ETC_OPENVPN_DIR/server.conf
# /etc/openvpn/easy-rsa.
ETC_OPENVPN_EASY_RSA_DIR=$ETC_OPENVPN_DIR/easy-rsa
ETC_OPENVPN_EASY_RSA_VARS_FILE=$ETC_OPENVPN_EASY_RSA_DIR/vars
# /etc/opevpn/easy-rsa/<version>.
ETC_OPENVPN_EASY_RSA_VERSION_NAME=3.0.8
ETC_OPENVPN_EASY_RSA_VERSION_DIR=$ETC_OPENVPN_EASY_RSA_DIR/$ETC_OPENVPN_EASY_RSA_VERSION_NAME
OPENVPN_SERVER_DIFFIE_HELLMAN_PEM_FILE=$ETC_OPENVPN_EASY_RSA_VERSION_DIR/dh.pem
OPENVPN_SERVER_TLS_AUTHENTICATION_KEY_FILE=$ETC_OPENVPN_EASY_RSA_VERSION_DIR/tls-auth.key
# /etc/openvpn/easy-rsa/<version>/pki.
ETC_OPENVPN_EASY_RSA_VERSION_PKI_DIR=$ETC_OPENVPN_EASY_RSA_VERSION_DIR/pki
OPENVPN_SERVER_CA_CERTIFICATE_FILE=$ETC_OPENVPN_EASY_RSA_VERSION_PKI_DIR/ca.crt
OPENVPN_SERVER_CRL_PEM_FILE=$ETC_OPENVPN_EASY_RSA_VERSION_PKI_DIR/crl.pem
# /etc/openvpn/easy-rsa/<version>/pki/issued.
ETC_OPENVPN_EASY_RSA_VERSION_PKI_ISSUED_DIR=$ETC_OPENVPN_EASY_RSA_VERSION_PKI_DIR/issued
OPENVPN_SERVER_SERVER_CERTIFICATE_FILE=$ETC_OPENVPN_EASY_RSA_VERSION_PKI_ISSUED_DIR/server.crt
# /etc/openvpn/easy-rsa/<version>/pki/private.
ETC_OPENVPN_EASY_RSA_VERSION_PKI_PRIVATE_DIR=$ETC_OPENVPN_EASY_RSA_VERSION_PKI_DIR/private
OPENVPN_SERVER_CA_KEY_FILE=$ETC_OPENVPN_EASY_RSA_VERSION_PKI_PRIVATE_DIR/ca.key
OPENVPN_SERVER_SERVER_KEY_FILE=$ETC_OPENVPN_EASY_RSA_VERSION_PKI_PRIVATE_DIR/server.key
# /usr.
USR_DIR=/usr
# /usr/share.
USR_SHARE_DIR=$USR_DIR/share
# /usr/share/easy-rsa.
USR_SHARE_EASY_RSA_DIR=$USR_SHARE_DIR/easy-rsa


### FUNCTIONS ###
INTERNAL_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
EXTERNAL_IP=$(curl ifconfig.me)
OPENVPN_PORT=1194
OPENVPN_PROTOCOL=udp
OPENVPNS_DNS=8.8.8.8
RSA_KEY_SIZE=2048
DH_KEY_SIZE=2048
CLIENT_NAME=client01
OPENVPN_SERVER_IP=10.0.8.0
OPENVPN_SERVER_NETMASK=255.255.255.0
OPENVPN_SERVER_SUBNET=24
CIPHER=AES-256-CBC


# Packages.
yum -y update
yum -y install epel-release
yum -y install easy-rsa openvpn

if [ -d $ETC_OPENVPN_EASY_RSA_DIR ]; then
	rm -rf $ETC_OPENVPN_EASY_RSA_DIR
fi
cp -r $USR_SHARE_EASY_RSA_DIR $ETC_OPENVPN_EASY_RSA_DIR

echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" > $ETC_OPENVPN_EASY_RSA_VARS_FILE

cd $ETC_OPENVPN_EASY_RSA_VERSION_DIR
echo "init-pki"
./easyrsa init-pki
echo "build-ca"
./easyrsa --batch build-ca nopass
echo "dhparam"
openssl dhparam $DH_KEY_SIZE -out $OPENVPN_SERVER_DIFFIE_HELLMAN_PEM_FILE
echo "build-server-full"
./easyrsa build-server-full server nopass
echo "build-client-full"
./easyrsa build-client-full $CLIENT_NAME nopass
echo "gen-crl"
./easyrsa gen-crl
echo "genkey"
openvpn --genkey --secret $OPENVPN_SERVER_TLS_AUTHENTICATION_KEY_FILE

ARRAY=($OPENVPN_SERVER_CA_CERTIFICATE_FILE $OPENVPN_SERVER_CA_KEY_FILE $OPENVPN_SERVER_DIFFIE_HELLMAN_PEM_FILE $OPENVPN_SERVER_SERVER_CERTIFICATE_FILE $OPENVPN_SERVER_SERVER_KEY_FILE $OPENVPN_SERVER_CRL_PEM_FILE)
for FILE in "${ARRAY[@]}"; do
	if [ -f $FILE ]; then
		cp $FILE $ETC_OPENVPN_DIR/
	else
		exit 1
	fi
done

chmod 644 $OPENVPN_SERVER_CRL_PEM_FILE

echo "create server.conf"
rm -f $ETC_OPENVPN_SERVER_CONF_FILE
echo "port $OPENVPN_PORT" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "proto $OPENVPN_PROTOCOL" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "dev tun" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "user nobody" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "group nogroup" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "persist-key" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "persist-tun" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "keepalive 10 120" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "topology subnet" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "server $OPENVPN_SERVER_IP $OPENVPN_SERVER_NETMASK" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "ifconfig-pool-persist ipp.txt" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo 'push "dhcp-option DNS $OPENVPNS_DNS"' >> $ETC_OPENVPN_SERVER_CONF_FILE
echo 'push "redirect-gateway def1 bypass-dhcp"' >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "crl-verify crl.pem" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "ca ca.crt" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "cert server.crt" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "key server.key" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "tls-auth tls-auth.key 0" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "dh dh.pem" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "auth SHA512" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "cipher $CIPHER" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "tls-server" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "tls-version-min 1.2" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "status openvpn.log" >> $ETC_OPENVPN_SERVER_CONF_FILE
echo "verb 3" >> $ETC_OPENVPN_SERVER_CONF_FILE

if [ ! -f $ETC_SYSTEM_CONFIGURATION_FILE ]; then
	touch $ETC_SYSTEM_CONFIGURATION_FILE
fi
sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' $ETC_SYSTEM_CONFIGURATION_FILE
echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -t nat -A POSTROUTING -s $OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET -j SNAT --to $INTERNAL_IP
sed -i "1 a\iptables -t nat -A POSTROUTING -s $OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET -j SNAT --to $INTERNAL_IP" /etc/rc.d/rc.local

iptables -I INPUT -p $OPENVPN_PROTOCOL --dport $OPENVPN_PORT -j ACCEPT
iptables -I FORWARD -s $OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET -j ACCEPT
iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

sed -i "1 a\iptables -I INPUT -p $OPENVPN_PROTOCOL --dport $OPENVPN_PORT -j ACCEPT" /etc/rc.d/rc.local
sed -i "1 a\iptables -I FORWARD -s $OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET -j ACCEPT" /etc/rc.d/rc.local
sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" /etc/rc.d/rc.local

yum install -y policycoreutils-python

semanage port -a -t openvpn_port_t -p $OPENVPN_PROTOCOL $OPENVPN_PORT

/etc/init.d/openvpn restart
chkconfig openvpn on

echo "Create the $CLIENT_NAME.ovpn..."
rm -f $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "client" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "proto $OPENVPN_PROTOCOL" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "remote $EXTERNAL_IP $OPENVPN_PORT" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "dev tun" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "resolv-retry infinite" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "nobind" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "persist-key" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "persist-tun" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "remote-cert-tls server" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "auth SHA512" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "cipher $CIPHER" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "tls-client" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "tls-version-min 1.2" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA512" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "setenv opt block-outside-dns" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "verb 3" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "<ca>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
cat $OPENVPN_SERVER_CA_CERTIFICATE_FILE >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "</ca>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "<cert>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
cat $ETC_OPENVPN_EASY_RSA_VERSION_PKI_ISSUED_DIR/$CLIENT_NAME.crt >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "</cert>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "<key>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
cat $ETC_OPENVPN_EASY_RSA_VERSION_PKI_PRIVATE_DIR/$CLIENT_NAME.key >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "</key>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "key-direction 1" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "<tls-auth>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
cat $ETC_OPENVPN_DIR/tls-auth.key >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
echo "</tls-auth>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
