# vpn-up-for-openconnect
VPN Up for OpenConnect

### Features ###

A shell script for openconnect which allows:
- to define multiple VPN connections
- to run openconnect without entering the username and password

### Sample configuration section ###

#Company VPN
export COM_NAME="My Company VPN"
export COM_HOST=vpn.mycompany.com
export COM_AUTHGROUP=developers
export COM_USER=sorin.ipate
export COM_PASSWD="MyPassword"

### Run VPN Up ###

% alias vpn-up='~/bin/vpn-up.command'
% vpn-up
