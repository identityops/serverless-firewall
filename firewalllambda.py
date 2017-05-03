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

def getErrorResponse(code, body):
    response = {
        "statusCode": code,
        "body": body
    }
    return response


###################
#
# Returns a set of ssh pubkeys from IAM
# Input:
#   userId : IAM userid

def sshkeys(event, context):

#     keyList = []
#     keyList.append('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDB8oEchsorCHBDWEfWRMqQRgbmOPrc+QWDg8iIkV9d8YqS0D5mixJ8amkc0N7TU3ETE3M/KVYaVjvilYsZ200O3PJLJsBNiaCyt4/TZh7df8Vi1SlgxbNtxAP33EfB74g5man+pLL3OWbX6S8ElxxXwWL8GkPZe3+0E3RjH9vYeqDw+iGXfhxF8FJjSCofcbVqJCLiGYUFudv6u/H7jjUpf2U2z2w0sKXlWZUwBSx+uWRauNUDr5oSptrzbSmOUYXK9CKV2aPwMcNdOVqyo/52QKtNKv8UZqCe3bmmgW5Y5htr1e89q1YGdd+T+hgfs8sqwf+EeRY8jvs97WBnL2vL')
#     keyList.append('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwg7iNWVwiZZUjexi/Foi0pZVMH83Y+3K3FNimQmsQyUmkttRqDRgBtJujGkviC3NkPn/dwuCNprJTBwH82pM8LpyvkFxaxUyyo/sYijpLUdAfKRJaoRbgCQN0E9BIIv6q31mCcztOIvRJznWyfDYEiXp6VV9OLr2dVrz8ov27hTXxBWf2P+coiogh/d3HXQjGDnTcBqlqrWG79RByRkhGGPiFB1YXWc8JCTrTDx6zcQR98gMFQAV9/ES4SpQIT0N18ZJBfMZBIbTvT2PlHBzoJ2nGbshILF08EmAvrDKeNHydqHbvHQgY0RdDMbWZ8KPlM9pCVjraJT1SMt502AoR')
#     response = {
#         "statusCode": 200,
#         "keys": json.dumps(keyList)
#     }
#     return response

    try:
        if 'userId' not in event['pathParameters']:
            return getErrorResponse(400, "No user id")

        userId = event['pathParameters']['userId']

        iam = boto3.client('iam')
        if iam is None:
            return getErrorResponse(500, "Can not initialize the system")

        try:
            userAcct = iam.get_user(UserName=userId)
            if userAcct is None:
                return getErrorResponse(404, "User doesnt exist in IAM")

        except:
            return getErrorResponse(404, "User doesnt exist in IAM")

        keys = iam.list_ssh_public_keys(UserName=userId)
        if keys is None:
            return getErrorResponse(404, "User has no keys")

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
            return getErrorResponse(404, "User has no active keys")

    except:
        print ('Error executing Firewall: %s' % str(sys.exc_info()[0]))
        return getErrorResponse(500, "Internal Error occurred")

