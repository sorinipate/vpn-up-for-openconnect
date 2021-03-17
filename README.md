# vpn-up-for-openconnect
VPN Up for OpenConnect

### Features ###

A shell script for openconnect which allows:</br>
- to define multiple VPN connections</br>
- to run openconnect without entering the username and password. 

### Sample configuration section ###

#Company VPN</br>
export COM_NAME="My Company VPN"</br>
export COM_HOST=vpn.mycompany.com</br>
export COM_AUTHGROUP=developers</br>
export COM_USER=sorin.ipate</br>
export COM_PASSWD="MyPassword"</br>

### Run VPN Up ###

% alias vpn-up='~/bin/vpn-up.command'</br>
% vpn-up</br>
