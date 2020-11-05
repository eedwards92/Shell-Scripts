###############################################################################
#!/bin/sh
###############################################################################
# Author:           DjRakso
# Date:             Thursday, November 5th, 2020
# Description:      Install and configure OpenVPN for RedHat systems. Creates 
#                   server and client configuration profiles.
# Compatability:    RedHat / CentOS 6/7/8
###############################################################################
# Copyright © by DjRakso 2020
###############################################################################



#####################
### USER SETTINGS ###
#####################
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
#####################


################
### COMMANDS ###
################
CONCATENATE_COMMAND=`which cat`
CHANGE_DIRECTORY_COMMAND="cd"
CHANGE_MODE_COMMAND="which chmod"
EXECUTE_CHANGE_MODE_COMMAND="$CHANGE_MODE_COMMAND +x"
CHECK_CONFIGURATION_SERVICES_COMMAND=`which chkconfig`
COPY_COMMAND=`which cp`
RECURSIVE_COPY_COMMAND="$COPY_COMMAND -r"
ECHO_COMMAND=`which echo`
EXIT_COMMAND="exit"
FIREWALL_COMMAND=`firewall-cmd`
IPTABLES_COMMAND=`which iptables`
OPENSSL_COMMAND=`which openssl`
OPENVPN_COMMAND=`which openvpn`
REMOVE_COMMAND=`which rm`
FORCE_REMOVE_COMMAND="$REMOVE_COMMAND -f"
RECURSIVE_FORCE_COPY_COMMAND="$REMOVE_COMMAND -rf"
SELINUX_POLICY_MANAGEMENT_COMMAND=`which semanage`
STREAM_EDITOR_COMMAND=`which sed`
SYSTEM_CONTROL_COMMAND=`which systemctl`
TOUCH_COMMAND=`which touch`
YUM_COMMAND=`which yum`
YUM_INSTALL_COMMAND="$YUM_COMMAND -y install"
YUM_UPDATE_COMMAND="$YUM_COMMAND -y update"
################


###########################
### FILES & DIRECTORIES ###
###########################
# /dev.
DEV_DIR=/dev
# /dev/net.
DEV_NET_DIR=$DEV_DIR/net
# /dev/net/tun.
DEV_NET_TUN_FILE=$DEV_NET_DIR/tun
# /etc.
ETC_DIR=/etc
ETC_SYSTEM_CONFIGURATION_FILE=$ETC_DIR/sysctl.conf
# /etc/init.d.
ETC_INIT_D_DIR=$ETC_DIR/init.d
OPENVPN_DAEMON=$ETC_INIT_D_DIR/openvpn
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
OPENVPN_SERVER_EASYRSA_COMMAND=$ETC_OPENVPN_EASY_RSA_VERSION_DIR/easyrsa
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
# /etc/rc.d.
ETC_RC_D_DIR=$ETC_DIR/rc.d
ETC_RC_D_RC_LOCAL_FILE=$ETC_RC_D_DIR/rc.local
# /proc.
PROC_DIR=/proc
PROC_SYS_DIR=$PROC_DIR/sys
PROC_SYS_NET_DIR=$PROC_SYS_DIR/net
PROC_SYS_NET_IPV4_DIR=$PROC_SYS_NET_DIR/ipv4
IP_FORWARD_FILE=$PROC_SYS_NET_IPV4_DIR/ip_forward
# /usr.
USR_DIR=/usr
# /usr/share.
USR_SHARE_DIR=$USR_DIR/share
# /usr/share/easy-rsa.
USR_SHARE_EASY_RSA_DIR=$USR_SHARE_DIR/easy-rsa
###########################


########################
### SYSTEM VARIABLES ###
########################
INTERNAL_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
EXTERNAL_IP=$(curl ifconfig.me)
OS_NAME=$(grep -oE '[a-Z]+' /etc/system-release | head -1)
OS_VERSION=$(grep -oE '[0-9]+' /etc/system-release | head -1)
########################


#################
### FUNCTIONS ###
#################
# Update the system packages.
$YUM_UPDATE_COMMAND
# Install the extra packages for enterprise linux. 
$YUM_INSTALL_COMMAND epel-release
# Install the easy rsa, openvpn and policy core utilities python packages.
$YUM_INSTALL_COMMAND easy-rsa openvpn policycoreutils-python

# Clean the /etc/opevpn/easy-rsa directory.
if [ -d $ETC_OPENVPN_EASY_RSA_DIR ]; then
	$RECURSIVE_FORCE_COPY_COMMAND $ETC_OPENVPN_EASY_RSA_DIR
fi

# Copy the default Easy-RSA directory to the OpenVPN directory.
$RECURSIVE_COPY_COMMAND $USR_SHARE_EASY_RSA_DIR $ETC_OPENVPN_EASY_RSA_DIR

# Set the RSA Key Size from the user settings.
$ECHO_COMMAND "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" > $ETC_OPENVPN_EASY_RSA_VARS_FILE

# Change to the specific OpenVPN Easy RSA version.
$CHANGE_DIRECTORY_COMMAND $ETC_OPENVPN_EASY_RSA_VERSION_DIR

# Generate a Diffie-Hellman file.
$OPENSSL_COMMAND dhparam $DH_KEY_SIZE -out $OPENVPN_SERVER_DIFFIE_HELLMAN_PEM_FILE
# Initialise your PKI.
.$OPENVPN_SERVER_EASYRSA_COMMAND init-pki
# Create your CA and disable password locking.
.$OPENVPN_SERVER_EASYRSA_COMMAND --batch build-ca nopass
# Build a server certificate & key and disable password locking.
.$OPENVPN_SERVER_EASYRSA_COMMAND build-server-full server nopass
# Build a client certificate & key and disable password locking.
.$OPENVPN_SERVER_EASYRSA_COMMAND build-client-full $CLIENT_NAME nopass
# Create your revoke certificate.
.$OPENVPN_SERVER_EASYRSA_COMMAND gen-crl
# Generate a TLS Authentication key.
$OPENVPN_COMMAND --genkey --secret $OPENVPN_SERVER_TLS_AUTHENTICATION_KEY_FILE

# Copy all these files to the OpenVPN directory.
ARRAY=($OPENVPN_SERVER_CA_CERTIFICATE_FILE $OPENVPN_SERVER_CA_KEY_FILE $OPENVPN_SERVER_DIFFIE_HELLMAN_PEM_FILE $OPENVPN_SERVER_SERVER_CERTIFICATE_FILE $OPENVPN_SERVER_SERVER_KEY_FILE $OPENVPN_SERVER_CRL_PEM_FILE)
for FILE in "${ARRAY[@]}"; do
	if [ -f $FILE ]; then
		$COPY_COMMAND $FILE $ETC_OPENVPN_DIR/
		if [ $FILE == $OPENVPN_SERVER_CRL_PEM_FILE ]; then
			$CHANGE_MODE_COMMAND 644 $FILE
		fi
	else
		$EXIT_COMMAND 1
	fi
done

# Remove the previous OpenVPN server configuration file.
$FORCE_REMOVE_COMMAND $ETC_OPENVPN_SERVER_CONF_FILE
# Create the OpenVPN server configuration file.
$ECHO_COMMAND "port $OPENVPN_PORT" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "proto $OPENVPN_PROTOCOL" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "dev tun" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "user nobody" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "group nogroup" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "persist-key" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "persist-tun" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "keepalive 10 120" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "topology subnet" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "server $OPENVPN_SERVER_IP $OPENVPN_SERVER_NETMASK" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "ifconfig-pool-persist ipp.txt" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND 'push "dhcp-option DNS $OPENVPNS_DNS"' >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND 'push "redirect-gateway def1 bypass-dhcp"' >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "crl-verify crl.pem" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "ca ca.crt" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "cert server.crt" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "key server.key" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "tls-auth tls-auth.key 0" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "dh dh.pem" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "auth SHA512" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "cipher $CIPHER" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "tls-server" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "tls-version-min 1.2" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "status openvpn.log" >> $ETC_OPENVPN_SERVER_CONF_FILE
$ECHO_COMMAND "verb 3" >> $ETC_OPENVPN_SERVER_CONF_FILE

# Touch the system configuration file if does not exist.
if [ ! -f $ETC_SYSTEM_CONFIGURATION_FILE ]; then
	$TOUCH_COMMAND $ETC_SYSTEM_CONFIGURATION_FILE
fi

# Enable IP forwarding.
$STREAM_EDITOR_COMMAND -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' $ETC_SYSTEM_CONFIGURATION_FILE
$ECHO_COMMAND 1 > $IP_FORWARD_FILE

if [ "$OS_VERSION" -eq 6 ]; then
	# Set the NAT Post routing rules for the OpenVPN server.
	$IPTABLES_COMMAND -t nat -A POSTROUTING -s $OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET -j SNAT --to $INTERNAL_IP
	$STREAM_EDITOR_COMMAND -i "1 a\iptables -t nat -A POSTROUTING -s $OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET -j SNAT --to $INTERNAL_IP" $ETC_RC_D_RC_LOCAL_FILE
	
	# Set the Firewall rules for the OpenVPN server.
	$IPTABLES_COMMAND -I INPUT -p $OPENVPN_PROTOCOL --dport $OPENVPN_PORT -j ACCEPT
	$IPTABLES_COMMAND -I FORWARD -s $OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET -j ACCEPT
	$IPTABLES_COMMAND -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	$STREAM_EDITOR_COMMAND -i "1 a\iptables -I INPUT -p $OPENVPN_PROTOCOL --dport $OPENVPN_PORT -j ACCEPT" $ETC_RC_D_RC_LOCAL_FILE
	$STREAM_EDITOR_COMMAND -i "1 a\iptables -I FORWARD -s $OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET -j ACCEPT" $ETC_RC_D_RC_LOCAL_FILE
	$STREAM_EDITOR_COMMAND -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $ETC_RC_D_RC_LOCAL_FILE
elif [ "$OS_VERSION" -gt 6 ]; then
	$FIREWALL_COMMAND --zone=public --add-port=$OPENVPN_PORT/$OPENVPN_PROTOCOL
	$FIREWALL_COMMAND --permanent --zone=public --add-port=$OPENVPN_PORT/$OPENVPN_PROTOCOL
	$FIREWALL_COMMAND --zone=trusted --add-source=$OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET
	$FIREWALL_COMMAND --permanent --zone=trusted --add-source=$OPENVPN_SERVER_IP/$OPENVPN_SERVER_SUBNET
else
	$EXIT_COMMAND 2
fi

# Set the SELinux Policy Management tool for OpenVPN protocol and port.
$SELINUX_POLICY_MANAGEMENT_COMMAND port -a -t openvpn_port_t -p $OPENVPN_PROTOCOL $OPENVPN_PORT

if [ "$OS_VERSION" -eq 6 ]; then
	# Restart the OpenVPN service.
	$OPENVPN_DAEMON restart
	# Add OpenVPN service to the system services.
	$CHECK_CONFIGURATION_SERVICES_COMMAND openvpn on
elif [ "$OS_VERSION" -gt 6 ]; then
	# Restart the OpenVPN service.
	$SYSTEM_CONTROL_COMMAND restart openvpn@server.service
	# Add OpenVPN service to the system services.
	$SYSTEM_CONTROL_COMMAND enable openvpn@server.service
else
	$EXIT_COMMAND 3
fi

# Remove the previous OpenVPN server configuration file.
$FORCE_REMOVE_COMMAND $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
# Create the OpenVPN client configuration file.
$ECHO_COMMAND "client" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
if [ "$OPENVPN_PROTOCOL" == "tcp" ]; then
	$ECHO_COMMAND "proto tcp-client"
else
	$ECHO_COMMAND "proto $OPENVPN_PROTOCOL" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
fi
$ECHO_COMMAND "remote $EXTERNAL_IP $OPENVPN_PORT" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "dev tun" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "resolv-retry infinite" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "nobind" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "persist-key" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "persist-tun" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "remote-cert-tls server" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "auth SHA512" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "cipher $CIPHER" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "tls-client" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "tls-version-min 1.2" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA512" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "setenv opt block-outside-dns" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "verb 3" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "<ca>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$CONCATENATE_COMMAND $OPENVPN_SERVER_CA_CERTIFICATE_FILE >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "</ca>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "<cert>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$CONCATENATE_COMMAND $ETC_OPENVPN_EASY_RSA_VERSION_PKI_ISSUED_DIR/$CLIENT_NAME.crt >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "</cert>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "<key>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$CONCATENATE_COMMAND $ETC_OPENVPN_EASY_RSA_VERSION_PKI_PRIVATE_DIR/$CLIENT_NAME.key >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "</key>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "key-direction 1" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "<tls-auth>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$CONCATENATE_COMMAND $OPENVPN_SERVER_TLS_AUTHENTICATION_KEY_FILE >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
$ECHO_COMMAND "</tls-auth>" >> $ETC_OPENVPN_DIR/$CLIENT_NAME.ovpn
#################

