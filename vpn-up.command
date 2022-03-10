#!/bin/bash

# Author: Sorin-Doru Ipate
# Edited by: Mohammad Amin Dadgar
# Copyright (c) Sorin-Doru Ipate

PROGRAM_NAME=$(basename $0)
echo "Starting $PROGRAM_NAME ..."

PID_FILE_PATH="${PWD}/${PROGRAM_NAME}.pid"
echo "Process ID (PID) stored in $PID_FILE_PATH ..."
LOG_FILE_PATH="${PWD}/${PROGRAM_NAME}.log"
echo "Logs stored in $LOG_FILE_PATH ..."

# OPTIONS

#   --background     Continue in background after startup
BACKGROUND=true

# VPN OPTION 1
export VPN1_NAME="VPN OPTION 1"
export VPN1_PROTOCOL=<protocol>
    # anyconnect       Compatible with Cisco AnyConnect SSL VPN, as well as ocserv (default)
    # nc               Compatible with Juniper Network Connect
    # gp               Compatible with Palo Alto Networks (PAN) GlobalProtect SSL VPN
    # pulse            Compatible with Pulse Connect Secure SSL VPN
export VPN1_HOST=<vpn.url>
export VPN1_AUTHGROUP=<group>
export VPN1_USER=<username>
export VPN1_PASSWD="<password>"
export VPN1_SERVER_CERTIFICATE=""  # SHA1 

# VPN OPTION 2
export VPN2_NAME="VPN OPTION 2"
export VPN2_PROTOCOL=<protocol>
    # anyconnect       Compatible with Cisco AnyConnect SSL VPN, as well as ocserv (default)
    # nc               Compatible with Juniper Network Connect
    # gp               Compatible with Palo Alto Networks (PAN) GlobalProtect SSL VPN
    # pulse            Compatible with Pulse Connect Secure SSL VPN
export VPN2_HOST=<vpn.url>
export VPN2_AUTHGROUP=<group>
export VPN2_USER=<username>
export VPN2_PASSWD="<password>"
export VPN2_SERVER_CERTIFICATE=""  # SHA1

function start(){

    if ! is_network_available
        then 
            printf "Network is not available! Please check your internet connection. \n"
            exit 1
    fi

    if is_vpn_running
        then
            printf "VPN is already running ... \n"
            exit 1
    fi

    echo "Which VPN do you want to connect to?"
    options=("$VPN1_NAME" "$VPN2_NAME" "Quit")
    select option in "${options[@]}";
        do
            case $option in
                "$VPN1_NAME")
                    export VPN_NAME=$VPN1_NAME
                    export VPN_HOST=$VPN1_HOST
                    export VPN_GROUP=$VPN1_AUTHGROUP
                    export VPN_USER=$VPN1_USER
                    export VPN_PASSWD=$VPN1_PASSWD
                    export SERVER_CERTIFICATE=$VPN1_SERVER_CERTIFICATE
                    export PROTOCOL=$VPN1_PROTOCOL
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
                    export PROTOCOL=$VPN2_PROTOCOL
                    connect
                    break
                    ;;
                "Quit")
                echo "User requested exit!"
                    exit
                    ;;
                *)
                echo "Invalid option $REPLY";; 
            esac
            if is_vpn_running
            then 
                printf "VPN is connected ... \n"
                print_current_ip_address
                break
            else
                printf "VPN failed to connect! \n"
        fi
        done
}

function connect(){
    if [[ -z $VPN_HOST ]]
        then
            echo "VPN_HOST environment variable not defined!"
            return
    fi
    if [[ -z $PROTOCOL ]]
        then
            echo "PROTOCOL variable not defined!"
            return
    fi
    
    case $PROTOCOL in
        "anyconnect")
            export PROTOCOL_DESCRIPTION="Cisco AnyConnect SSL VPN"
            ;;
        "nc")
            export PROTOCOL_DESCRIPTION="Juniper Network Connect"
            ;;
        "gp")
            export PROTOCOL_DESCRIPTION="Palo Alto Networks (PAN) GlobalProtect SSL VPN"
            ;;
        "pulse")
            export PROTOCOL_DESCRIPTION="Pulse Connect Secure SSL VPN"
            ;;
    esac
        
    echo "Starting the $VPN_NAME on $VPN_HOST using $PROTOCOL_DESCRIPTION ..."
    

    if [ "$SERVER_CERTIFICATE" = "" ]
        then
            echo "Connecting without server certificate ..."
            if [ "$BACKGROUND" = true ]
                then
                    echo "Running the $VPN_NAME in background ..."
                    echo $VPN_PASSWD | sudo openconnect --protocol=$PROTOCOL --background -q $VPN_HOST --user=$VPN_USER --authgroup=$VPN_GROUP --passwd-on-stdin --pid-file $PID_FILE_PATH > $LOG_FILE_PATH 2>&1
                else
                    echo "Running the $VPN_NAME ..."
                    echo $VPN_PASSWD | sudo openconnect --protocol=$PROTOCOL -q $VPN_HOST --user=$VPN_USER --authgroup=$VPN_GROUP --passwd-on-stdin --pid-file $PID_FILE_PATH > $LOG_FILE_PATH 2>&1
                fi
        else
            echo "Connecting with certificate ..."
            if [ "$BACKGROUND" = true ]
                then
                    echo "Running the $VPN_NAME in background ..."
                    echo $VPN_PASSWD | sudo openconnect --protocol=$PROTOCOL --background -q $VPN_HOST --user=$VPN_USER --authgroup=$VPN_GROUP --passwd-on-stdin --servercert=$SERVER_CERTIFICATE --pid-file $PID_FILE_PATH > $LOG_FILE_PATH 2>&1
                else
                    echo "Running the $VPN_NAME ..."
                    echo $VPN_PASSWD | sudo openconnect --protocol=$PROTOCOL -q $VPN_HOST --user=$VPN_USER --authgroup=$VPN_GROUP --passwd-on-stdin --servercert=$SERVER_CERTIFICATE --pid-file $PID_FILE_PATH > $LOG_FILE_PATH 2>&1
                fi
        fi
    status
}

function status() {
    is_vpn_running && printf "VPN is running ... \n" || printf "VPN is stopped ... \n"
    print_current_ip_address
}

function stop() {

    if is_vpn_running
        then
            echo "VPN is running ... Removing $PID_FILE_PATH ..."
            
            # kill -9 $(pgrep openconnect) > /dev/null 2>&1
            local pid=$(cat $PID_FILE_PATH)
            kill -9 $pid > /dev/null 2>&1
            rm -f $PID_FILE_PATH > /dev/null 2>&1
    fi
    
    printf "VPN is disconnected! \n"
    print_current_ip_address
}

function print_info() {
    echo "Usage: $(basename "$0") (start|stop|status|restart)"
}

function is_network_available() {
    ping -q -c 1 -W 1 8.8.8.8 > /dev/null 2>&1;
}

function is_vpn_running() {
    test -f $PID_FILE_PATH && return 0
     #local pid=$(cat $PID_FILE_PATH)
    # kill -0 $pid > /dev/null 2>&1
}

function print_current_ip_address() {
    local ip=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com)
    printf "Your IP address is $ip \n"
}

case "$1" in

	start)
	
		start
		;;
	
	stop)
	
		stop
		;;
	
	status)
	
		status
		;;
	
	restart)
	
		$0 stop
		$0 start
		;;
	
	*)
	
		print_info
		exit 0
		;;
esac