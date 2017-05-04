#!/bin/bash

################################################
#	Copyright (c) 2015 zibernetics inc.
#
# This file is part of ziNet
#
# ziNet is free software: you can redistribute it and/or modify
# it under the terms of the Apache License as published by
# the Apache Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# ziNet is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# Apache License for more details.
#
# You should have received a copy of the Apache License
# along with ziNet.  If not, see <http://www.apache.org/licenses/LICENSE-2.0>.
#
################################################

SCRIPT=$(readlink -f $0)
SCRIPTPATH=$(dirname ${SCRIPT})
DIRNAME=$(basename ${SCRIPTPATH})

SAVE_DIR=$(pwd)
cd ${SCRIPTPATH}

if [[ $(id -un) != root ]]; then
		echo "#### This script must be run as root."
		exit 0
fi

localSecretsFile=

USAGE="	Usage: `basename $0`  -Y secretsFile"

while getopts hY: OPT; do
    case "$OPT" in
        h)
            echo $USAGE
            exit 0
            ;;
        Y)
            localSecretsFile="$OPTARG"
            ;;
        \?)
            # getopts issues an error message
            echo $USAGE >&2
            exit 1
            ;;
    esac
done

if [ ! -f "${localSecretsFile}" ]; then
	echo "Must pass a valid secrets file"
    echo $USAGE >&2
    cd ${SAVE_DIR}
    exit 1
fi

################################################
#
#	Main program
#
################################################

localSLUser=firewall

BACKOUT_DATE=$(date +%Y%m%d-%H%M%S)

echo "#### Starting install of ${localSLUser}"
groupadd ${localSLUser}
useradd -s /bin/false -g ${localSLUser} ${localSLUser}

echo "#### Creating config figuration"
cp "${localSecretsFile}" /etc/default/${localSLUser}
chown root:${localSLUser} /etc/default/${localSLUser}
chmod 640 /etc/default/${localSLUser}

echo "#### Installing ${localSLUser} package"
/bin/cp -f ${SCRIPTPATH}/firewall-*.py /usr/local/bin/
chmod 650 /usr/local/bin/firewall-*.py
chown root:${localSLUser} /usr/local/bin/${localSLUser}-*.py

echo "#### Configure SSH server"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.${BACKOUT_DATE}
grep 'AuthorizedKeysCommand' /etc/ssh/sshd_config > /dev/null && {
	sed -i "s|^[ \t;]*\(AuthorizedKeysCommand\)[ \t]* .*|\1 /usr/local/bin/firewall-pubkey.py|g" /etc/ssh/sshd_config
} || {
    echo "AuthorizedKeysCommand /usr/local/bin/firewall-pubkey.py" >> /etc/ssh/sshd_config
}

grep 'AuthorizedKeysCommandUser' /etc/ssh/sshd_config > /dev/null && {
	sed -i "s|^[ \t;]*\(AuthorizedKeysCommandUser\)[ \t]* .*|\1 ${localSLUser}|g" /etc/ssh/sshd_config
} || {
    echo "AuthorizedKeysCommandUser ${localSLUser}" >> /etc/ssh/sshd_config
}

echo "#### Restart SSH server"
service ssh restart

# echo "#### Configure PAM - Add pam_access.so"
# cp /etc/pam.d/common-account /etc/pam.d/common-account.${BACKOUT_DATE}
# grep 'pam_access.so' /etc/pam.d/common-account > /dev/null || {
# cat >> /etc/pam.d/common-account <<EOF
# account [success=2 default=ignore] pam_succeed_if.so uid < 1000 quiet
# account sufficient pam_exec.so quiet /usr/local/bin/firewall-authz.py
# account required pam_deny.so
# account required pam_access.so
# EOF
# }

echo "#### Configure PAM - /etc/pam.d/common-auth"
mv /etc/pam.d/common-auth /etc/pam.d/common-auth.${BACKOUT_DATE}
cat > /etc/pam.d/common-auth <<EOF
auth [success=1 default=ignore] pam_succeed_if.so uid >= 1000 quiet
auth sufficient pam_unix.so nullok_secure
auth [success=2 default=ignore] pam_succeed_if.so uid < 1000 quiet
# auth sufficient pam_ldap.so use_first_pass
auth required pam_deny.so
EOF

echo "#### Remove use_authtok from /etc/pam.d/common-password"
cp /etc/pam.d/common-password /etc/pam.d/common-password.${BACKOUT_DATE}
sed -i -r 's/(.*)(use_authtok)(.*)/\1\3/g' /etc/pam.d/common-password

echo "#### Add pam_mkhomedir.so to  /etc/pam.d/common-session"
cp /etc/pam.d/common-session /etc/pam.d/common-session.${BACKOUT_DATE}
cat > /etc/pam.d/common-session <<EOF
session [default=1]     pam_permit.so
session requisite       pam_deny.so
session required        pam_permit.so
session optional        pam_umask.so
session required        pam_unix.so
# session optional        pam_ldap.so
session optional        pam_systemd.so
session required        pam_mkhomedir.so skel=/etc/skel umask=0022
EOF

# echo "#### Edit /etc/security/access.conf"
# cp /etc/security/access.conf /etc/security/access.conf.${BACKOUT_DATE}
# 
# oldHostIds=$(netrcGetMachines ${sshldapHomeDir}/.netrc)
# if [ ! -z "${oldHostIds}" ]; then
#     echo "#### Got old host list: $oldHostIds"
#     sed -i '/^- : ALL EXCEPT/d' /etc/security/access.conf
#     while read -r i; do
#         sed -i "/${i}/d" /etc/security/access.conf
#         sed -i "/${i}-sudo/d" /etc/security/access.conf
#     done <<< "${oldHostIds}"
# fi
# 
# echo "#### add the new host configuration"
# IFS=',' read -ra theHosts  <<< "$localHostId"
# for j in "${theHosts[@]}"; do
#     echo "+ : (${j}) : ALL" >> /etc/security/access.conf
#     echo "+ : (${j}-sudo) : ALL" >> /etc/security/access.conf
# done
# echo "- : ALL EXCEPT root (admin) (wheel) (sshldap_admins) ${SSHLDAP_SECURITY_GRPS} : ALL EXCEPT LOCAL" >> /etc/security/access.conf
# 
# echo "#### Creating /etc/sudoers.d/${localSLUser}"
# rm /etc/sudoers.d/${localSLUser} 2>/dev/null
# for k in "${theHosts[@]}"; do
#     echo "%${k}-sudo ALL=(ALL) ALL" >> /etc/sudoers.d/${localSLUser}
# done
# echo "%sshldap_admins ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/${localSLUser}
# chmod 440 /etc/sudoers.d/${localSLUser}

echo "#### Serverless firewall installation complete"
