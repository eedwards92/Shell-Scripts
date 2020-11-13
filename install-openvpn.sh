###############################################################################
#!/bin/sh
###############################################################################
# Author:           DjRakso
# Date:             Friday, November 13th, 2020
# Description:      Install and configure OpenVPN for RedHat systems. Creates 
#                   server and client configuration profiles.
# Compatability:    CentOS/RedHat 6/7/8
###############################################################################
# Copyright © by DjRakso 2020
###############################################################################



#####################
### USER SETTINGS ###
#####################
FORCE_SYSTEM_UPDATE=1
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
EXTERNAL_IP_ADDRESS=""
#####################


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
# /etc/openvpn/clients
ETC_OPENVPN_CLIENTS_DIR=$ETC_OPENVPN_DIR/clients
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
OPENVPN_SERVER_INDEX_TXT_FILE=$ETC_OPENVPN_EASY_RSA_VERSION_PKI_DIR/index.txt
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
OS_NAME=$(grep -oE '[a-Z]+' /etc/system-release | head -1)
OS_VERSION=$(grep -oE '[0-9]+' /etc/system-release | head -1)
########################


#################
### FUNCTIONS ###
#################
# Is running as root user.
function IsRootUser() {
	if [ "$EUID" -ne 0 ]; then
		$ECHO_COMMAND "You need to run as root user."
		return 1
	fi
}

# Load the system commands.
function LoadSystemCommands() {
	CONCATENATE_COMMAND=`which cat`
	CHANGE_DIRECTORY_COMMAND="cd"
	CHANGE_MODE_COMMAND=`which chmod`
	EXECUTE_CHANGE_MODE_COMMAND="$CHANGE_MODE_COMMAND +x"
	CHECK_CONFIGURATION_SERVICES_COMMAND=`which chkconfig`
	COPY_COMMAND=`which cp`
	FORCE_COPY_COMMAND="$COPY_COMMAND -f"
	RECURSIVE_COPY_COMMAND="$COPY_COMMAND -r"
	FORCE_RECURSIVE_COPY_COMMAND="$COPY_COMMAND -rf"
	CUT_COMMAND=`which cut`
	ECHO_COMMAND=`which echo`
	EXIT_COMMAND="exit"
	GREP_COMMAND=`which grep`
	OPENSSL_COMMAND=`which openssl`
	OPENVPN_COMMAND=`which openvpn`
	REMOVE_COMMAND=`which rm`
	FORCE_REMOVE_COMMAND="$REMOVE_COMMAND -f"
	RECURSIVE_FORCE_COPY_COMMAND="$REMOVE_COMMAND -rf"
	SELINUX_POLICY_MANAGEMENT_COMMAND=`which semanage`
	STREAM_EDITOR_COMMAND=`which sed`
	TOUCH_COMMAND=`which touch`
	YUM_COMMAND=`which yum`
	YUM_INSTALL_COMMAND="$YUM_COMMAND -y install"
	YUM_UPDATE_COMMAND="$YUM_COMMAND -y update"
	# CentOS 6
	if [ "$OS_VERSION" -eq 6 ]; then
		IPTABLES_COMMAND=`which iptables`
		SYSTEM_CONTROL_COMMAND=`which service`
	# CentOS 7+
	elif [ "$OS_VERSION" -ge 7 ]; then
		FIREWALL_COMMAND=`which firewall-cmd`
		SYSTEM_CONTROL_COMMAND=`which systemctl`
	fi
}

# Delete a specific file.
function DeleteFile() {
	FILE=${1}
	if [ -f $FILE ]; then
		$ECHO_COMMAND "The $FILE file does exist."
		$ECHO_COMMAND "Deleting the $FILE file..."
		$FORCE_REMOVE_COMMAND -f $FILE
		if [ ! -f $FILE ]; then
			$ECHO_COMMAND "Successfully deleted the $FILE file."
		else
			$ECHO_COMMAND "Could not successfully delete the $FILE file."
			return 1
		fi
	else
		$ECHO_COMMAND "Already successfully removed the $FILE file."
	fi
}

# Touch a specific file.
function TouchFile() {
	FILE=${1}
	if [ ! -f $FILE ]; then
		$ECHO_COMMAND "The $FILE file does not exist."
		$ECHO_COMMAND "Touching the $FILE file..."
		$TOUCH_COMMAND $FILE
		if [ -f $FILE ]; then
			$ECHO_COMMAND "Successfully touched the $FILE file."
		else
			$ECHO_COMMAND "Could not successfully touch the $FILE file."
			return 1
		fi
	else
		$ECHO_COMMAND "The $FILE file does exist."
	fi
}

# Create a directory.
function CreateDirectory() {
	DIRECTORY=${1}
	if [ ! -d $DIRECTORY ]; then
		$ECHO_COMMAND "Creating the $DIRECTORY directory..."
		mkdir -p $DIRECTORY
		if [ -d $DIRECTORY ]; then
			$ECHO_COMMAND "Successfully created the $DIRECTORY directory."
		else
			$ECHO_COMMAND "Could not successfully create the $DIRECTORY directory."
		fi
	else
		$ECHO_COMMAND "Already create the $DIRECTORY directory."
	fi
}

# Change to a specific directory.
function ChangeDirectory() {
	DIRECTORY=${1}
	if [ -d $DIRECTORY ]; then
		$CHANGE_DIRECTORY_COMMAND $DIRECTORY
		if [ "`pwd`" == "$DIRECTORY" ]; then
			$ECHO_COMMAND "Successfully changed to the $DIRECTORY directory."
		else
			$ECHO_COMMAND "Could not successfully change to the $DIRECTORY directory."
		fi
	else
		$ECHO_COMMAND "[ERROR] The $DIRECTORY directory does not exist."
		exit 1
	fi
}

# Clean the specific directory.
function CleanDirectory() {
	DIRECTORY=${1}
	if [ -d $DIRECTORY ]; then
		$ECHO_COMMAND "The $DIRECTORY directory does exist."
		$ECHO_COMMAND "Removing the $DIRECTORY directory..."
		$RECURSIVE_FORCE_COPY_COMMAND $DIRECTORY
		if [ ! -d $DIRECTORY ]; then
			$ECHO_COMMAND "Successfully removed the $DIRECTORY directory."
		else
			$ECHO_COMMAND "Could not successfully remove the $DIRECTORY directory."
			return 1
		fi
	else
		$ECHO_COMMAND "Already successfully removed the $DIRECTORY directory."
	fi
}

# Copy a specific file to specific directory.
function CopyFileToDirectory() {
	FILE="${1}"
	DIRECTORY="${2}"
	if [ ! -z "$FILE" ] && [ ! -z "$DIRECTORY" ]; then
		$FORCE_COPY_COMMAND $FILE $DIRECTORY
		FILE_NAME=$(echo ${FILE##*/})
		NEW_FILE=$DIRECTORY/$FILE_NAME
		if [ -f $NEW_FILE ]; then
			$ECHO_COMMAND "Successfully copied the $NEW_FILE file to the $DIRECTORY directory."
		else
			$ECHO_COMMAND "Could not successfully copy the $NEW_FILE file to the $DIRECTORY directory."
		fi
	else
		if [ -z "$FILE" ]; then
			VARIABLE=FILE
		elif [ -z "$DIRECTORY" ]; then
			VARIABLE=DIRECTORY
		fi
		$ECHO_COMMAND "[ERROR] The $VARIABLE variable is empty."
		exit 1
	fi
}

# Copy a specific directory to another directory.
function CopyDirectoryToAnotherDirectory() {
	FROM_DIRECTORY=${1}
	TO_DIRECTORY=${2}
	if [ ! -z "$FROM_DIRECTORY" ] && [ ! -z "$TO_DIRECTORY" ]; then
		$RECURSIVE_COPY_COMMAND $FROM_DIRECTORY $TO_DIRECTORY
	else
		if [ -z "$FROM_DIRECTORY" ]; then
			VARIABLE=FROM_DIRECTORY
		elif [ -z "$TO_DIRECTORY" ]; then
			VARIABLE=TO_DIRECTORY
		fi
		$ECHO_COMMAND "[ERROR] The $VARIABLE variable is empty."
		exit 1
	fi
}

# Enable the service.
function EnableService() {
	SERVICE="${1}"
	if [ ! -z "$SERVICE" ]; then
		if [ "$OS_VERSION" -eq 6 ]; then
			# Add OpenVPN service to the system services.
			$CHECK_CONFIGURATION_SERVICES_COMMAND $SERVICE on
		elif [ "$OS_VERSION" -gt 6 ]; then
			# Add OpenVPN service to the system services.
			$SYSTEM_CONTROL_COMMAND enable $SERVICE@server.service
		else
			$EXIT_COMMAND 3
		fi
	else
		$ECHO_COMMAND "[ERROR] The $SERVICE service is not valid."
		$EXIT_COMMAND 3
	fi
}

# Restart the service.
function RestartService() {
	SERVICE="${1}"
	if [ ! -z "$SERVICE" ]; then
		if [ "$OS_VERSION" -eq 6 ]; then
			# Restart the OpenVPN service.
			service $SERVICE restart
		elif [ "$OS_VERSION" -gt 6 ]; then
			# Restart the OpenVPN service.
			$SYSTEM_CONTROL_COMMAND restart $SERVICE@server.service
		else
			$EXIT_COMMAND 3
		fi
	else
		$ECHO_COMMAND "[ERROR] The $SERVICE service is not valid."
		$EXIT_COMMAND 3
	fi
}

# Add a line to a new file.
function AddLineToNewFile() {
	LINE="${1}"
	FILE="${2}"
	if [ ! -z "$LINE" ] && [ ! -z "$FILE" ]; then
		$ECHO_COMMAND "$LINE" > $FILE
	else
		if [ -z "$LINE" ]; then
			VARIABLE=LINE
		elif [ -z "$FILE" ]; then
			VARIABLE=FILE
		fi
		$ECHO_COMMAND "[ERROR] The $VARIABLE variable is empty."
		exit 1
	fi
}

# Add a line to a file.
function AddLineToFile() {
	LINE="${1}"
	FILE="${2}"
	if [ ! -z "$LINE" ] && [ ! -z "$FILE" ]; then
		$ECHO_COMMAND "$LINE" >> $FILE
	else
		if [ -z "$LINE" ]; then
			VARIABLE=LINE
		elif [ -z "$FILE" ]; then
			VARIABLE=FILE
		fi
		$ECHO_COMMAND "[ERROR] The $VARIABLE variable is empty."
		exit 1
	fi
}

# Replace line to line.
function ReplaceFromLineToLineFile() {
	SEARCH_KEY="${1}"
	NEW_VALUE="${2}"
	ADD_SPACES="${3}"
	FILE="${4}"
	if [ "$ADD_SPACES" == "yes" ]; then
		ADD_SPACES=" "
	fi
	if [ ! -z "$SEARCH_KEY" ] && [ ! -z "$NEW_VALUE" ]; then
		FROM_LINE_VALUE="`$CONCATENATE_COMMAND $FILE | $GREP_COMMAND $SEARCH_KEY | $CUT_COMMAND -d'=' -f2 | xargs`"
		if [ "$NEW_VALUE" != "$FROM_LINE_VALUE" ]; then
			FROM_LINE="$SEARCH_KEY$ADD_SPACES=$ADD_SPACES$FROM_LINE_VALUE"
			TO_LINE="$SEARCH_KEY$ADD_SPACES=$ADD_SPACES$NEW_VALUE"
			$STREAM_EDITOR_COMMAND -i "s|${FROM_LINE}|${TO_LINE}|g" $FILE
			SUCCESS="`$CONCATENATE_COMMAND $FILE | $GREP_COMMAND $SEARCH_KEY`"
			if [ "$SUCCESS" == "$SEARCH_KEY$ADD_SPACES=$ADD_SPACES$NEW_VALUE" ]; then
				$ECHO_COMMAND "Successfully replaced $SEARCH_KEY from $FROM_LINE_VALUE to $NEW_VALUE from the $FILE file."
			else
				$ECHO_COMMAND "Could not successfully replace $SEARCH_KEY from $FROM_LINE_VALUE to $NEW_VALUE from the $FILE file."
			fi
		else
			SUCCESS="`$CONCATENATE_COMMAND $FILE | $GREP_COMMAND $SEARCH_KEY`"
			if [ "$SUCCESS" == "$SEARCH_KEY$ADD_SPACES=$ADD_SPACES$NEW_VALUE" ]; then
				$ECHO_COMMAND "Already successfully replaced $SEARCH_KEY from $FROM_LINE_VALUE to $NEW_VALUE from the $FILE file."
			else
				$ECHO_COMMAND "[ERROR] Could not successfully replace $SEARCH_KEY from $FROM_LINE_VALUE to $NEW_VALUE from the $FILE file."
			fi
		fi
	else
		if [ -z "$SEARCH_KEY" ]; then
			VARIABLE=SEARCH_KEY
		elif [ -z "$NEW_VALUE" ]; then
			VARIABLE=NEW_VALUE
		fi
		$ECHO_COMMAND "[ERROR] The $VARIABLE variable is empty."
		exit 1
	fi
}

# Retrieve the external IP address.
function RetrieveExternalIPAddress() {
	# Return 0 for true.
	INTERNET_STATUS=$(ping -c 1 -q ifconfig.me >&/dev/null; echo $?)
	if [ "$INTERNET_STATUS" -eq 0 ]; then
		EXTERNAL_IP_ADDRESS=$(curl -s ifconfig.me)
	else
		$ECHO_COMMAND "Using default external IP address from user settings."
	fi
}

# Update YUM packages.
function UpdateYumPackages() {
	if [ "$FORCE_SYSTEM_UPDATE" -eq 0 ]; then
		$ECHO_COMMAND "Performing a system update..."
		$YUM_UPDATE_COMMAND
	else
		$ECHO_COMMAND "Not performing a system update."
	fi
}

# Install YUM packages.
function InstallYumPackage() {
	PACKAGE_NAME=${1}
	if [ -z "`rpm -qa $PACKAGE_NAME`" ]; then
		$YUM_INSTALL_COMMAND $PACKAGE_NAME
	else
		$ECHO_COMMAND "This $PACKAGE_NAME package has been already installed."
	fi
}

# Is the tunnel bridge available.
function IsTunnelBridgeAvailable() {
	if [ ! -e $DEV_NET_TUN_FILE ]; then
		$ECHO_COMMAND "The Tunnel Bridge is not available."
		return 1
	fi
}

# System checks.
function SystemChecks() {
	if [ ! IsRootUser ]; then
		exit 1
	fi
	if [ ! IsTunnelBridgeAvailable ]; then
		exit 1
	fi
}

# Set the OpenVPN server Firewall profile.
function SetOpenVPNServerFirewallProfile() {
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
}

# Copy all these files to the OpenVPN directory.
function CopyOpenVPNFilesToDirectory() {
	ARRAY=($OPENVPN_SERVER_CA_CERTIFICATE_FILE $OPENVPN_SERVER_CA_KEY_FILE $OPENVPN_SERVER_DIFFIE_HELLMAN_PEM_FILE $OPENVPN_SERVER_SERVER_CERTIFICATE_FILE $OPENVPN_SERVER_SERVER_KEY_FILE $OPENVPN_SERVER_CRL_PEM_FILE $OPENVPN_SERVER_TLS_AUTHENTICATION_KEY_FILE)
	for FILE in "${ARRAY[@]}"; do
		if [ -f $FILE ]; then
			CopyFileToDirectory $FILE $ETC_OPENVPN_DIR
			if [ $FILE == $OPENVPN_SERVER_CRL_PEM_FILE ]; then
				$CHANGE_MODE_COMMAND 644 $FILE
			fi
		else
			$EXIT_COMMAND 1
		fi
	done
}

# Create the OpenVPN server configuration file.
function CreateOpenVPNServerConfigurationFile() {
	FILE="${1}"
	if [ -f $FILE ]; then
		DeleteFile $FILE
	fi
	if [ ! -f $FILE ]; then
		$ECHO_COMMAND "port $OPENVPN_PORT" >> $FILE
		$ECHO_COMMAND "proto $OPENVPN_PROTOCOL" >> $FILE
		$ECHO_COMMAND "dev tun" >> $FILE
		$ECHO_COMMAND "user nobody" >> $FILE
		$ECHO_COMMAND "group nogroup" >> $FILE
		$ECHO_COMMAND "persist-key" >> $FILE
		$ECHO_COMMAND "persist-tun" >> $FILE
		$ECHO_COMMAND "keepalive 10 120" >> $FILE
		$ECHO_COMMAND "topology subnet" >> $FILE
		$ECHO_COMMAND "server $OPENVPN_SERVER_IP $OPENVPN_SERVER_NETMASK" >> $FILE
		$ECHO_COMMAND "ifconfig-pool-persist ipp.txt" >> $FILE
		$ECHO_COMMAND 'push "dhcp-option DNS $OPENVPNS_DNS"' >> $FILE
		$ECHO_COMMAND 'push "redirect-gateway def1 bypass-dhcp"' >> $FILE
		$ECHO_COMMAND "crl-verify crl.pem" >> $FILE
		$ECHO_COMMAND "ca ca.crt" >> $FILE
		$ECHO_COMMAND "cert server.crt" >> $FILE
		$ECHO_COMMAND "key server.key" >> $FILE
		$ECHO_COMMAND "tls-auth tls-auth.key 0" >> $FILE
		$ECHO_COMMAND "dh dh.pem" >> $FILE
		$ECHO_COMMAND "auth SHA512" >> $FILE
		$ECHO_COMMAND "cipher $CIPHER" >> $FILE
		$ECHO_COMMAND "tls-server" >> $FILE
		$ECHO_COMMAND "tls-version-min 1.2" >> $FILE
		$ECHO_COMMAND "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384" >> $FILE
		$ECHO_COMMAND "status openvpn.log" >> $FILE
		$ECHO_COMMAND "verb 3" >> $FILE
	fi
}

# Create the OpenVPN client configuration file.
function CreateOpenVPNClientConfigurationFile() {
	CLIENT_NAME="${1}"
	FILE=$ETC_OPENVPN_CLIENTS_DIR/$CLIENT_NAME.ovpn
	if [ -f $FILE ]; then
		DeleteFile $FILE
	fi
	if [ ! -f $FILE ]; then
		$ECHO_COMMAND "client" >> $FILE
		if [ "$OPENVPN_PROTOCOL" == "tcp" ]; then
			$ECHO_COMMAND "proto tcp-client"
		else
			$ECHO_COMMAND "proto $OPENVPN_PROTOCOL" >> $FILE
		fi
		$ECHO_COMMAND "remote $EXTERNAL_IP_ADDRESS $OPENVPN_PORT" >> $FILE
		$ECHO_COMMAND "dev tun" >> $FILE
		$ECHO_COMMAND "resolv-retry infinite" >> $FILE
		$ECHO_COMMAND "nobind" >> $FILE
		$ECHO_COMMAND "persist-key" >> $FILE
		$ECHO_COMMAND "persist-tun" >> $FILE
		$ECHO_COMMAND "remote-cert-tls server" >> $FILE
		$ECHO_COMMAND "auth SHA512" >> $FILE
		$ECHO_COMMAND "cipher $CIPHER" >> $FILE
		$ECHO_COMMAND "tls-client" >> $FILE
		$ECHO_COMMAND "tls-version-min 1.2" >> $FILE
		$ECHO_COMMAND "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA512" >> $FILE
		$ECHO_COMMAND "setenv opt block-outside-dns" >> $FILE
		$ECHO_COMMAND "verb 3" >> $FILE
		$ECHO_COMMAND "<ca>" >> $FILE
		$CONCATENATE_COMMAND $OPENVPN_SERVER_CA_CERTIFICATE_FILE >> $FILE
		$ECHO_COMMAND "</ca>" >> $FILE
		$ECHO_COMMAND "<cert>" >> $FILE
		$CONCATENATE_COMMAND $ETC_OPENVPN_EASY_RSA_VERSION_PKI_ISSUED_DIR/$CLIENT_NAME.crt >> $FILE
		$ECHO_COMMAND "</cert>" >> $FILE
		$ECHO_COMMAND "<key>" >> $FILE
		$CONCATENATE_COMMAND $ETC_OPENVPN_EASY_RSA_VERSION_PKI_PRIVATE_DIR/$CLIENT_NAME.key >> $FILE
		$ECHO_COMMAND "</key>" >> $FILE
		$ECHO_COMMAND "key-direction 1" >> $FILE
		$ECHO_COMMAND "<tls-auth>" >> $FILE
		$CONCATENATE_COMMAND $OPENVPN_SERVER_TLS_AUTHENTICATION_KEY_FILE >> $FILE
		$ECHO_COMMAND "</tls-auth>" >> $FILE
	fi
}
#################


############
### MAIN ###
############
# System checks.
SystemChecks

# Install and configure the OpenVPN server.
function InstallOpenVPNServer() {
	# Update the system packages.
	UpdateYumPackages
	# Install the extra packages for enterprise linux. 
	InstallYumPackage epel-release
	# Install the easy rsa, openvpn and policy core utilities python packages.
	InstallYumPackage easy-rsa 
	InstallYumPackage openvpn
	InstallYumPackage policycoreutils-python

	# Clean the /etc/opevpn/easy-rsa directory.
	CleanDirectory $ETC_OPENVPN_DIR

	# Create the new OpenVPN Easy-RSA directory.
	CreateDirectory $ETC_OPENVPN_DIR
	
	# Copy the default Easy-RSA directory to the OpenVPN directory.
	CopyDirectoryToAnotherDirectory $USR_SHARE_EASY_RSA_DIR $ETC_OPENVPN_EASY_RSA_DIR

	# Set the RSA Key Size from the user settings.
	AddLineToNewFile "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" $ETC_OPENVPN_EASY_RSA_VARS_FILE

	# Change to the specific OpenVPN Easy RSA version.
	ChangeDirectory $ETC_OPENVPN_EASY_RSA_VERSION_DIR

	# Generate a Diffie-Hellman file.
	$OPENSSL_COMMAND dhparam $DH_KEY_SIZE -out $OPENVPN_SERVER_DIFFIE_HELLMAN_PEM_FILE
	# Initialise your PKI.
	. $OPENVPN_SERVER_EASYRSA_COMMAND init-pki
	# Create your CA and disable password locking.
	. $OPENVPN_SERVER_EASYRSA_COMMAND --batch build-ca nopass
	# Build a server certificate & key and disable password locking.
	. $OPENVPN_SERVER_EASYRSA_COMMAND build-server-full server nopass
	# Create your revoke certificate.
	. $OPENVPN_SERVER_EASYRSA_COMMAND gen-crl
	# Generate a TLS Authentication key.
	$OPENVPN_COMMAND --genkey --secret $OPENVPN_SERVER_TLS_AUTHENTICATION_KEY_FILE

	# Copy all these files to the OpenVPN directory.
	CopyOpenVPNFilesToDirectory

	# Remove the previous OpenVPN server configuration file.
	DeleteFile $ETC_OPENVPN_SERVER_CONF_FILE

	# Create the OpenVPN server configuration file.
	CreateOpenVPNServerConfigurationFile $ETC_OPENVPN_SERVER_CONF_FILE

	# Touch the system configuration file if does not exist.
	TouchFile $ETC_SYSTEM_CONFIGURATION_FILE

	# Enable IP forwarding.
	ReplaceFromLineToLineFile "net.ipv4.ip_forward" "1" "yes" $ETC_SYSTEM_CONFIGURATION_FILE
	AddLineToNewFile 1 $IP_FORWARD_FILE

	# Set the OpenVPN server Firewall profile.
	SetOpenVPNServerFirewallProfile

	# Set the SELinux Policy Management tool for OpenVPN protocol and port.
	$SELINUX_POLICY_MANAGEMENT_COMMAND port -a -t openvpn_port_t -p $OPENVPN_PROTOCOL $OPENVPN_PORT

	# Add the OpenVPN service.
	EnableService openvpn

	# Restart the OpenVPN service.
	RestartService openvpn
	
	clear
	if [ "$INSTALLED" == "0" ]; then
		$ECHO_COMMAND "Successfully reinstalled the OpenVPN server."
	else
		$ECHO_COMMAND "Successfully installed the OpenVPN server."
	fi
	$ECHO_COMMAND ""
}

# Create an OpenVPN client profile.
function CreateOpenVPNClientProfile() {
	read -p "Enter a client name: " ClientNameSelect
	
	if [ ! -z "$ClientNameSelect" ]; then
		LIST_CLIENT_NAMES=(`ls $ETC_OPENVPN_CLIENTS_DIR | $CUT_COMMAND -d'.' -f 1`)
		for ITEM in "${LIST_CLIENT_NAMES[@]}"; do
			if [ "$ITEM" == "$ClientNameSelect" ]; then
				$ECHO_COMMAND "Sorry, this client name already exist. Please try again!"
				$ECHO_COMMAND ""
				CreateOpenVPNClientProfile
			fi
		done
		
		# Change to the specific OpenVPN Easy RSA version.
		ChangeDirectory $ETC_OPENVPN_EASY_RSA_VERSION_DIR
		
		# Build a client certificate & key and disable password locking.
		. $OPENVPN_SERVER_EASYRSA_COMMAND build-client-full $ClientNameSelect nopass
		
		# Create the OpenVPN clients directory if it doesn't exist.
		CreateDirectory $ETC_OPENVPN_CLIENTS_DIR
		
		# Remove the previous OpenVPN client profile configuration file.
		DeleteFile $ETC_OPENVPN_CLIENTS_DIR/$ClientNameSelect.ovpn
		
		# Retrieve the external IP address.
		RetrieveExternalIPAddress
		
		# Create the OpenVPN client configuration file.
		CreateOpenVPNClientConfigurationFile $ClientNameSelect
		
		clear
		$ECHO_COMMAND "Successfully created the $ClientNameSelect OpenVPN client profile."
		$ECHO_COMMAND ""
	else
		$ECHO_COMMAND "Sorry, no name was entered. Please try again!"
		$ECHO_COMMAND ""
	fi
}

# Revoke OpenVPN Client Profile.
function RevokeOpenVPNClientProfile() {
	clear
	if [ -e $OPENVPN_SERVER_INDEX_TXT_FILE ]; then
		NUMBER_OF_CLIENTS=$(tail -n +2 $OPENVPN_SERVER_INDEX_TXT_FILE | $GREP_COMMAND -c "^V")
		if [ "$NUMBER_OF_CLIENTS" -eq 0 ]; then
			$ECHO_COMMAND "You have no existing OpenVPN client profiles."
			$ECHO_COMMAND ""
			MainMenu
		else
			$ECHO_COMMAND "You have a total of $NUMBER_OF_CLIENTS OpenVPN client profiles below:"
			NAMES_OF_CLIENTS=$(tail -n +2 $OPENVPN_SERVER_INDEX_TXT_FILE | $GREP_COMMAND "^V" | $CUT_COMMAND -d'=' -f 2)
			$ECHO_COMMAND "$NAMES_OF_CLIENTS"
			$ECHO_COMMAND ""
			read -p "Select a client name to revoke: " ClientNameSelect	

			if [ ! -z "$ClientNameSelect" ]; then
				DOES_EXIST=1
				LIST_CLIENT_NAMES=(`ls $ETC_OPENVPN_CLIENTS_DIR | cut -d'.' -f 1`)
				for ITEM in "${LIST_CLIENT_NAMES[@]}"; do
					if [ "$ITEM" == "$ClientNameSelect" ]; then
						DOES_EXIST=0
						break
					fi
				done
				
				if [ "$DOES_EXIST" -eq 0 ]; then
					# Change to the specific OpenVPN Easy RSA version.
					ChangeDirectory $ETC_OPENVPN_EASY_RSA_VERSION_DIR
					
					# Revoke the OpenVPN client profile.
					. $OPENVPN_SERVER_EASYRSA_COMMAND --batch revoke $ClientNameSelect
					
					# Delete the OpenVPN configuration client profile.
					DeleteFile $ETC_OPENVPN_CLIENTS_DIR/$ClientNameSelect.ovpn
					
					clear
					$ECHO_COMMAND "Successfully revoked and deleted the $ClientNameSelect OpenVPN client profile."
					$ECHO_COMMAND ""
				else
					$ECHO_COMMAND "The OpenVPN client profile $ClientNameSelect does not exist."
					$ECHO_COMMAND ""
				fi
			else
				$ECHO_COMMAND "Sorry, no name was entered. Please try again!"
				$ECHO_COMMAND ""
				RevokeOpenVPNClientProfile
			fi
		fi
	else
		$ECHO_COMMAND "The server is incorrectly configured, exiting..."
		exit 1
	fi
}

# List all the current OpenVPN client profiles.
function ListOpenVPNClientProfile() {
	clear
	if [ -e $OPENVPN_SERVER_INDEX_TXT_FILE ]; then
		NUMBER_OF_CLIENTS=$(tail -n +2 $OPENVPN_SERVER_INDEX_TXT_FILE | $GREP_COMMAND -c "^V")
		NAMES_OF_CLIENTS=$(tail -n +2 $OPENVPN_SERVER_INDEX_TXT_FILE | $CUT_COMMAND -d'=' -f 2)
		$ECHO_COMMAND "You have a total of $NUMBER_OF_CLIENTS OpenVPN client profiles below:"
		$ECHO_COMMAND "$NAMES_OF_CLIENTS"
		$ECHO_COMMAND ""
		read -p "Press the [Enter] key to return back to the Main Menu: " EnterKey
		clear
	fi
}

# Main menu.
function MainMenu() {
	LoadSystemCommands
	while :
	do
		if [ -e $ETC_OPENVPN_SERVER_CONF_FILE ]; then
			INSTALLED=0
		fi
		$ECHO_COMMAND "What would you like to perform: "
		if [ "$INSTALLED" == "0" ]; then
			$ECHO_COMMAND "  1) Reinstall OpenVPN server"
		else
			$ECHO_COMMAND "  1) Install OpenVPN server"
		fi
		$ECHO_COMMAND "  2) Create a new OpenVPN client profile"
		$ECHO_COMMAND "  3) Revoke an existing OpenVPN client profile(s)"
		$ECHO_COMMAND "  4) List available OpenVPN client profile(s)"
		$ECHO_COMMAND "  5) Exit"
		$ECHO_COMMAND ""
		read -p "Select: " MainMenuOption
		case $MainMenuOption in
			1) clear;
			InstallOpenVPNServer;
			MainMenu;;
			2) clear;
			CreateOpenVPNClientProfile;
			MainMenu;;
			3) clear;
			RevokeOpenVPNClientProfile;
			MainMenu;;
			4) clear;
			ListOpenVPNClientProfile;
			MainMenu;;
			5) clear;
			exit;;
		esac
	done
}

clear
MainMenu