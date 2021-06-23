#!/bin/bash

# Author: Sorin-Doru Ipate
# Edited by: Mohammad Amin Dadgar
# Copyright (c) Sorin-Doru Ipate

#VPN OPTION 1
#If you don't have the server certificate don't edit it
export VPN1_NAME="VPN OPTION 1"
export VPN1_HOST=<vpn.url>
export VPN1_AUTHGROUP=<group>
export VPN1_USER=<username>
export VPN1_PASSWD="<password>"
export VPN1_SERVER_CERTIFICATE="<vpn.servercert>"  # SHA 

#VPN OPTION 2
export VPN2_NAME="VPN OPTION 2"
export VPN2_HOST=<vpn.url>
export VPN2_AUTHGROUP=<group>
export VPN2_USER=<username>
export VPN2_PASSWD="<password>"
export VPN2_SERVER_CERTIFICATE="<vpn.servercert>"  # SHA 

function start(){
    echo "Which VPN do you want to connect to?"
    options=("$VPN1_NAME" "$VPN2_NAME" "Quit")
    select option in "${options[@]}"; do
        case $option in
        "$VPN1_NAME")
            export VPN_NAME=$VPN1_NAME
            export VPN_HOST=$VPN1_HOST
            export VPN_GROUP=$VPN1_AUTHGROUP
            export VPN_USER=$VPN1_USER
            export VPN_PASSWD=$VPN1_PASSWD
            export VPN_CERTIFICATE=$VPN1_SERVER_CERTIFICATE
            connect
            break
            ;;
        "$VPN2_NAME")
            export VPN_NAME=$VPN2_NAME
            export VPN_HOST=$VPN2_HOST
            export VPN_GROUP=$VPN2_AUTHGROUP
            export VPN_USER=$VPN2_USER
            export VPN_PASSWD=$VPN2_PASSWD
            export SERVER_CERTIFICATE=$VPN2_SERVER_CERTIFICATE
            connect
            break
            ;;
        "Quit")
        echo "User requested exit"
            exit
            ;;
        *) echo "invalid option $REPLY";; 
        esac
    done
}

function connect(){
    if [[ -z $VPN_HOST ]]
        then
            echo "VPN_HOST environment variable missing..."
            return
        fi
    echo "Starting the $VPN_NAME... for $VPN_HOST"
    echo "Connecting..."
    if [[ $SERVER_CERTIFICATE == "<vpn.servercert>" ]]
        then
            echo "Connecting without server certificate"
            echo $VPN_PASSWD | sudo openconnect --background $VPN_HOST --user=$VPN_USER --passwd-on-stdin --authgroup=$VPN_GROUP
        else
            echo "Connecting with certificate"
            echo $VPN_PASSWD | sudo openconnect --background $VPN_HOST --user=$VPN_USER --passwd-on-stdin --authgroup=$VPN_GROUP --servercert=$SERVER_CERTIFICATE
        fi
    
}

echo "Start of script..."

start
