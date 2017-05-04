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

sshUserId="${1}"
if [ -z "${sshUserId}" ]; then
    sshUserId="${PAM_USER}"
fi

if [ -z "${sshUserId}" ]; then
    logger -i -t Firewall -p info "No user credentials passed (PAM_CRED_INSUFFICIENT)"
    exit 11
fi

source /etc/default/firewall 2>/dev/null
if [ $? -ne 0 ]; then
    logger -i -t Firewall -p info "Error reading serverless firewall default runtime"
	exit 1
fi

if [ -z "${SL_FIREWALL_API_KEY}" ]; then
    logger -i -t Firewall -p info "Error SL_FIREWALL_API_KEY is not defined"
	exit 1

fi

if [ -z "${SL_FIREWALL_AUTHZ_EP}" ]; then
    logger -i -t Firewall -p info "Error SL_FIREWALL_AUTHZ_EP is not defined"
	exit 1
fi

logger -i -t Firewall -p info "Starting authorization processing for user: ${sshUserId}"

userAuthorized=false

machineId=$(curl http://169.254.169.254/latest/meta-data/instance-id)
if [ -z "${machineId}" ]; then
    logger -i -t Firewall -p info "Error reading machine id"
	exit 1
fi

curl -s -o /dev/null -w "%{http_code}" -H "x-api-key: ${SL_FIREWALL_API_KEY}" -H "Cache-Control: no-cache" ${SL_FIREWALL_AUTHZ_EP}/${sshUserId}/${machineId}


if $userAuthorized; then
    logger -i -t Firewall -p info "User ${sshUserId} is authorized"   
    exit 0
else
    logger -i -t Firewall -p info "User ${sshUserId} is NOT authorized (PAM_PERM_DENIED)"
    exit 7
fi
