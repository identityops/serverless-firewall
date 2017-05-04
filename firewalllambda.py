################################################
#	Copyright (c) 2017 zibernetics inc.
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

import json
import boto3
import sys
import logging

def getResponse(code, body):
    response = {
        "statusCode": code,
        "body": body
    }
    return response


############################################################################
#
# Returns a set of ssh pubkeys from IAM
# Input:
#   pathParameters.userId : IAM userid
#
############################################################################

def sshkeys(event, context):

    try:
        if 'userId' not in event['pathParameters']:
            return getResponse(400, "No user id")

        userId = event['pathParameters']['userId']

        iam = boto3.client('iam')
        if iam is None:
            return getResponse(500, "Can not initialize the system")

        try:
            userAcct = iam.get_user(UserName=userId)
            if userAcct is None:
                return getResponse(404, "User doesnt exist in IAM")

        except:
            return getResponse(404, "User doesnt exist in IAM")

        keys = iam.list_ssh_public_keys(UserName=userId)
        if keys is None:
            return getResponse(404, "User has no keys")

        keyList = []
        for key in keys['SSHPublicKeys']:
            keyId = key['SSHPublicKeyId']
            keyDetail = iam.get_ssh_public_key(UserName=userId,SSHPublicKeyId=keyId,Encoding='SSH')['SSHPublicKey']
            status = keyDetail['Status']
            if status == "Active":
                keyList.append(keyDetail['SSHPublicKeyBody'])

        if len(keyList) > 0:
            response = {
                'statusCode': 200,
                'body': json.dumps(keyList)
            }
            return response
        else:
            return getResponse(404, "User has no active keys")

    except:
        print ('Error executing Firewall: %s' % str(sys.exc_info()[0]))
        return getResponse(500, "Internal Error occurred")


############################################################################
#
# Determines if a user is authorized to access a serverGroups
# Depends on ec2 instances with tags named fwgroup
#
# Input:
#   pathParameters.instanceId
#
############################################################################

def authz(event, context):
    try:
        if 'pathParameters' not in event:
            return getResponse(400, "No parameters passed")

        if 'userId' not in event['pathParameters']:
            return getResponse(400, "No user id")

        if 'instanceId' not in event['pathParameters']:
            return getResponse(400, "No instance id")

        userId = event['pathParameters']['userId']
        instanceId = event['pathParameters']['instanceId']

        iam = boto3.client('iam')
        if iam is None:
            return getResponse(500, "Can not initialize the system")

        ec2 = boto3.client('ec2')
        if ec2 is None:
            return getResponse(500, "Can not initialize the system")

        tagList = ec2.describe_tags(Filters=[
            {'Name': 'key', 'Values': ['fwgroup']},
            {'Name': 'resource-type', 'Values': ['instance']},
            {'Name': 'resource-id', 'Values': [instanceId]}
        ])
        if 'Tags' not in tagList:
            return getResponse(404, "No groups found in for instance: %s" % instanceId )

        serverGroups = []
        for tag in tagList['Tags']:
            serverGroups.append(tag['Value'])

        # always append the FirewallAdmins super user group
        serverGroups.append('FirewallAdmins')

        userGroups = []
        groupList=iam.list_groups_for_user(UserName=userId)
        for group in groupList['Groups']:
            userGroups.append(group['GroupName'])

        assignedGroups=set(serverGroups).intersection(userGroups)
        if len(assignedGroups) > 0:
            return getResponse(200, "%s is authorized" % userId)
        else:
            return getResponse(401, "%s is not authorized" % userId)

    except:
        print ('Error executing Firewall: %s' % str(sys.exc_info()[0]))
        return getResponse(500, "Internal Error occurred")

