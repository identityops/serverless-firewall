#!/bin/bash

echo "SL_FIREWALL_API_KEY='<<YOUR KEY>>'" > ~/.secrets
echo "SL_FIREWALL_SSHKEY_EP='<<YOUR SSHKEY URL>>/dev/sshkeys'" >> ~/.secrets
echo "SL_FIREWALL_AUTHZ_EP='<<YOUR AUTHZ EP>>/dev/authz'" >> ~/.secrets
echo "SL_FIREWALL_API_DEBUG=True" >> ~/.secrets
chmod 400 ~/.secrets

sudo apt-get install -y git python
git clone git@github.com:identityops/serverless-firewall.git
cd serverless-firewall/
sudo ./install-firewall.sh -Y ~/.secrets
rm ~/.secrets

sudo useradd chris
sudo useradd rolf
sudo useradd zig
