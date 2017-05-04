#! /usr/bin/env python

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

import urllib2
import sys
import json
import syslog

def getKey(sshUserId):
    sshKeys = ''

    try:
        try:
            with open( '/'.join(('/etc/default', 'firewall')) ) as fd:
                exec( fd.read() )
                fd.close()
        except:
            syslog.syslog( syslog.LOG_DEBUG, 'Firewall: Error opening firewall config' )
            return
       
        if SL_FIREWALL_API_DEBUG:
            syslog.setlogmask( syslog.LOG_UPTO(syslog.LOG_DEBUG) )

        syslog.syslog( syslog.LOG_DEBUG, 'Firewall: Received key request for user: %s ' % sshUserId )

        req = urllib2.Request('%s/%s' % (SL_FIREWALL_HOST, sshUserId))
        req.add_header('x-api-key', SL_FIREWALL_API_KEY)
        req.add_header('Cache-Control', 'no-cache')

        try:
            resp = urllib2.urlopen(req)
            content = resp.read()
            keyList = json.loads(content)
            
            if keyList is not None:
                numKeys = 0
                for key in keyList:
                    if numKeys > 0:
                        sshKeys += '\n'
                    sshKeys += key
                    numKeys += 1
            else:
                syslog.syslog( syslog.LOG_ALERT, 'Firewall: No keys returned for user %' % sshUserId )

            resp.close()        

        except urllib2.HTTPError as e:
            if e.code >= 400 and e.code < 500:
                syslog.syslog( syslog.LOG_ALERT, 'Firewall: Parameter error for user %, Err: %s ' % ( sshUserId, e.read() ) )
            else:
                syslog.syslog( syslog.LOG_ERR, 'Firewall: Internal error for user %, Err: %s ' % ( sshUserId, e.read() ) )
    except:
        syslog.syslog( syslog.LOG_ALERT, "Firewall: Internal error opening config properties: %s" % str(sys.exc_info()[0]) )

    return sshKeys

if __name__ == "__main__":
    if  len(sys.argv) > 1:
        print (getKey(sys.argv[1]))
    else:
        print ''
