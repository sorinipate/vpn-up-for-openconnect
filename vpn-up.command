#!/bin/bash

# Author: Sorin-Doru Ipate (@sorinipate)
# Edited by: Mohammad Amin Dadgar (@amindadgar)
# Edited by: Shunsuke Kitada (@shunk031)
# Copyright (c) Sorin-Doru Ipate

PROGRAM_NAME=$(basename "$0")
PROGRAM_PATH=${PWD}

CONFIGURATION_FILE="${PROGRAM_PATH}/config/${PROGRAM_NAME}.config"
PROFILES_FILE="${PROGRAM_PATH}/config/${PROGRAM_NAME}.profiles"

PID_FILE_PATH="${PROGRAM_PATH}/logs/${PROGRAM_NAME}.pid"
LOG_FILE_PATH="${PROGRAM_PATH}/logs/${PROGRAM_NAME}.log"

function start() {

    if ! does_configuration_file_exist
        then
            printf "%b" "${DANGER}"
            printf "Configuration file missing! \n"
            printf "%b" "${RESET}"
            exit 1
        else
            source $CONFIGURATION_FILE
            printf "%b" "${WARNING}"
            printf "Loaded configuration from $CONFIGURATION_FILE ...\n"
            printf "%b" "${RESET}"
    fi

    if ! does_profiles_file_exist
        then
            printf "%b" "${DANGER}"
            printf "Profiles file missing! \n"
            printf "%b" "${RESET}"
            exit 1
        else
            source $PROFILES_FILE
            printf "%b" "${WARNING}"
            printf "Loaded profiles from $PROFILES_FILE ...\n"
            printf "%b" "${RESET}"
    fi
    
    if ! is_network_available; then
        printf "%b" "${DANGER}"
        printf "Please check your internet connection or try again later!\n"
        printf "%b" "${RESET}"
        exit 1
    fi

    if is_vpn_running; then
        printf "%b" "${WARNING}"
        printf "Already connected to a VPN!\n"
        printf "%b" "${RESET}"
        exit 1
    fi

    if [ "$SUDO" = TRUE ]; then
        if [[ -z $SUDO_PASSWORD ]]; then
            printf "%b" "${DANGER}"
            printf "Variable 'SUDO_PASSWORD' is not declared! Update the variable 'SUDO_PASSWORD' declaration in ${CONFIGURATION_FILE} ...\n"
            printf "%b" "${RESET}"
            return
        else
            cat sudo -S <<<"${SUDO_PASSWORD}"
            printf "%b" "${WARNING}"
            printf "Running as root ...\n"
            printf "%b" "${RESET}"
        fi
    else
        printf "%b" "${WARNING}"
        printf "Running as normal user! OpenConnect requires to be executed with root privileges; please enter the root password when prompted...\n"
        printf "%b" "${RESET}"

    fi

    printf "%b" "${PRIMARY}"
    printf "Starting %s ...\n" "${PROGRAM_NAME}"
    printf "%b" "${RESET}"

    printf "%b" "${WARNING}"
    printf "Process ID (PID) stored in %s ...\n" "${PID_FILE_PATH}"
    printf "%b" "${RESET}"

    printf "%b" "${WARNING}"
    printf "Logs file (LOG) stored in %s ...\n" "${LOG_FILE_PATH}"
    printf "%b" "${RESET}"

    printf "%b" "${PRIMARY}"
    printf "Which VPN do you want to connect to?\n"
    options=("$VPN1_NAME" "$VPN2_NAME" "Quit")
    printf "%b" "${RESET}"
    select option in "${options[@]}"; do
        case $option in
        "$VPN1_NAME")
            export VPN_NAME=$VPN1_NAME
            export VPN_HOST=$VPN1_HOST
            export VPN_GROUP=$VPN1_AUTHGROUP
            export VPN_USER=$VPN1_USER
            export VPN_PASSWD=$VPN1_PASSWD
            export VPN_DUO2FAMETHOD=$VPN1_DUO2FAMETHOD
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
            export VPN_DUO2FAMETHOD=$VPN2_DUO2FAMETHOD
            export SERVER_CERTIFICATE=$VPN2_SERVER_CERTIFICATE
            export PROTOCOL=$VPN2_PROTOCOL
            connect
            break
            ;;
        "Quit")
            printf "%b" "${WARNING}"
            printf "You chose to close the app!\n"
            printf "%b" "${RESET}"
            exit
            ;;
        *)

            printf "%b" "${DANGER}"
            printf "Invalid option! Please choose one of the options above...\n"
            printf "%b" "${RESET}"
            printf "%b" "${REPLY}"
            ;;
        esac
    done
    if is_vpn_running; then
        printf "%b" "${SUCCESS}"
        printf "Connected to %s\n" "${VPN_NAME}"
        print_current_ip_address
        printf "%b" "${RESET}"
    else
        printf "%b" "${DANGER}"
        printf "Failed to connect!\n"
        printf "%b" "${RESET}"
    fi
}

function connect() {
    if [[ -z "${VPN_HOST}" ]]; then
        printf "%b" "${DANGER}"
        printf "Variable 'VPN_HOST' is not declared! Update the variable 'VPN_HOST' declaration in ${PROFILES_FILE} ...\n"
        printf "%b" "${RESET}"
        return
    fi
    if [[ -z $PROTOCOL ]]; then
        printf "%b" "${DANGER}"
        printf "Variable 'PROTOCOL' is not declared! Update the variable 'PROTOCOL' declaration in ${PROFILES_FILE} ..."
        printf "%b" "${RESET}"
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
    *)
        printf "%b" "${DANGER}"
        printf "Unsupported protocol! Update the variable 'PROTOCOL' declaration in ${PROFILES_FILE} ..."
        printf "%b" "${RESET}"
        return
        ;;
    esac

    case $VPN_DUO2FAMETHOD in
    "push")
        export VPN_DUO2FAMETHOD_DESCRIPTION="PUSH"
        ;;
    "phone")
        export VPN_DUO2FAMETHOD_DESCRIPTION="PHONE"
        ;;
    "sms")
        export VPN_DUO2FAMETHOD_DESCRIPTION="SMS"
        ;;
    "")
        export VPN_DUO2FAMETHOD_DESCRIPTION="NONE"
        ;;
    *)
        if [[ "$VPN_DUO2FAMETHOD" =~ ^[0-9]{6}$ ]]; then
            export VPN_DUO2FAMETHOD_DESCRIPTION="PASSCODE"
        else
            printf "%b" "${DANGER}"
            printf "Unsupported PASSCODE format! Update the variable 'VPN_DUO2FAMETHOD' declaration in ${PROFILES_FILE} ..."
            printf "%b" "${RESET}"
            return
        fi
        ;;
    esac

    printf "%b" "${PRIMARY}"
    printf "Starting the %s on %s using %s ...\n" "${VPN_NAME}" "${VPN_HOST}" "${PROTOCOL_DESCRIPTION}"
    printf "%b" "${RESET}"

    if [ "$VPN_DUO2FAMETHOD" = "" ]; then
        printf "%b" "${WARNING}"
        printf "Connecting without 2FA (%s) ...\n" "${VPN_DUO2FAMETHOD_DESCRIPTION}"
        printf "%b" "${RESET}"
        if [ "$SERVER_CERTIFICATE" = "" ]; then
            printf "%b" "${WARNING}"
            printf "Connecting without server certificate ...\n"
            printf "%b" "${RESET}"
            if [ "$BACKGROUND" = TRUE ]; then
                printf "%b" "${PRIMARY}"
                printf "Running the %s in background ...\n" "${VPN_NAME}"
                printf "%b" "${RESET}"
                if [ "$QUIET" = TRUE ]; then
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with less output (quiet) ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    echo $VPN_PASSWD | sudo openconnect --protocol="${PROTOCOL}" --background -q "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                else
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with detailed output ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    echo $VPN_PASSWD | sudo openconnect --protocol="${PROTOCOL}" --background "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                fi
            else
                printf "%b" "${PRIMARY}"
                printf "Running the %s ...\n" "${VPN_NAME}"
                printf "%b" "${RESET}"
                if [ "$QUIET" = TRUE ]; then
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with less output (quiet) ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    echo $VPN_PASSWD | sudo openconnect --protocol="${PROTOCOL}" -q "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                else
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with detailed output ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    echo $VPN_PASSWD | sudo openconnect --protocol="${PROTOCOL}" "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                fi
            fi
        else
            printf "%b" "${PRIMARY}"
            printf "Connecting with certificate ...\n"
            printf "%b" "${RESET}"
            if [ "$BACKGROUND" = TRUE ]; then
                printf "%b" "${PRIMARY}"
                printf "Running the %s in background ...\n" "${VPN_NAME}"
                printf "%b" "${RESET}"
                if [ "$QUIET" = TRUE ]; then
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with less output (quiet) ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    echo $VPN_PASSWD | sudo openconnect --protocol="${PROTOCOL}" --background -q "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --servercert="${SERVER_CERTIFICATE}" --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                else
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with detailed output ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    echo $VPN_PASSWD | sudo openconnect --protocol="${PROTOCOL}" --background "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --servercert="${SERVER_CERTIFICATE}" --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                fi
            else
                printf "%b" "${PRIMARY}"
                printf "Running the %s ...\n" "${VPN_NAME}"
                printf "%b" "${RESET}"
                if [ "$QUIET" = TRUE ]; then
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with less output (quiet) ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    echo $VPN_PASSWD | sudo openconnect --protocol="${PROTOCOL}" -q "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --servercert="${SERVER_CERTIFICATE}" --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                else
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with detailed output ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    echo $VPN_PASSWD | sudo openconnect --protocol="${PROTOCOL}" "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --servercert="${SERVER_CERTIFICATE}" --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                fi
            fi
        fi

    else
        printf "%b" "${PRIMARY}"
        printf "Connecting with Two-Factor Authentication (2FA) from Duo (%s) ...\n" "${VPN_DUO2FAMETHOD_DESCRIPTION}"
        printf "%b" "${RESET}"
        if [ "$SERVER_CERTIFICATE" = "" ]; then
            printf "%b" "${WARNING}"
            printf "Connecting without server certificate ...\n"
            printf "%b" "${RESET}"
            if [ "$BACKGROUND" = TRUE ]; then
                printf "%b" "${PRIMARY}"
                printf "Running the %s in background ...\n" "${VPN_NAME}"
                printf "%b" "${RESET}"
                if [ "$QUIET" = TRUE ]; then
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with less output (quiet) ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    {
                        echo $VPN_PASSWD
                        sleep 1
                        echo $VPN_DUO2FAMETHOD
                    } | sudo openconnect --protocol="${PROTOCOL}" --background -q "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                else
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with detailed output ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    {
                        echo $VPN_PASSWD
                        sleep 1
                        echo $VPN_DUO2FAMETHOD
                    } | sudo openconnect --protocol="${PROTOCOL}" --background "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                fi
            else
                printf "%b" "${PRIMARY}"
                printf "Running the %s ...\n" "${VPN_NAME}"
                printf "%b" "${RESET}"
                if [ "$QUIET" = TRUE ]; then
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with less output (quiet) ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    {
                        echo $VPN_PASSWD
                        sleep 1
                        echo $VPN_DUO2FAMETHOD
                    } | sudo openconnect --protocol="${PROTOCOL}" -q "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                else
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with detailed output ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    {
                        echo $VPN_PASSWD
                        sleep 1
                        echo $VPN_DUO2FAMETHOD
                    } | sudo openconnect --protocol="${PROTOCOL}" "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                fi
            fi
        else
            printf "%b" "${PRIMARY}"
            printf "Connecting with certificate ...\n"
            printf "%b" "${RESET}"
            if [ "$BACKGROUND" = TRUE ]; then
                printf "%b" "${PRIMARY}"
                printf "Running the %s in background ...\n" "${VPN_NAME}"
                printf "%b" "${RESET}"
                if [ "$QUIET" = TRUE ]; then
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with less output (quiet) ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    {
                        echo $VPN_PASSWD
                        sleep 1
                        echo $VPN_DUO2FAMETHOD
                    } | sudo openconnect --protocol="${PROTOCOL}" --background -q "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --servercert="${SERVER_CERTIFICATE}" --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                else
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with detailed output ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    {
                        echo $VPN_PASSWD
                        sleep 1
                        echo $VPN_DUO2FAMETHOD
                    } | sudo openconnect --protocol="${PROTOCOL}" --background "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --servercert="${SERVER_CERTIFICATE}" --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                fi
            else
                printf "%b" "${PRIMARY}"
                printf "Running the %s ...\n" "${VPN_NAME}"
                printf "%b" "${RESET}"
                if [ "$QUIET" = TRUE ]; then
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with less output (quiet) ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    {
                        echo $VPN_PASSWD
                        sleep 1
                        echo $VPN_DUO2FAMETHOD
                    } | sudo openconnect --protocol="${PROTOCOL}" -q "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --servercert="${SERVER_CERTIFICATE}" --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                else
                    printf "%b" "${PRIMARY}"
                    printf "Running the %s with detailed output ...\n" "${VPN_NAME}"
                    printf "%b" "${RESET}"
                    {
                        echo $VPN_PASSWD
                        sleep 1
                        echo $VPN_DUO2FAMETHOD
                    } | sudo openconnect --protocol="${PROTOCOL}" "${VPN_HOST}" --user="${VPN_USER}" --authgroup="${VPN_GROUP}" --passwd-on-stdin --servercert="${SERVER_CERTIFICATE}" --pid-file "${PID_FILE_PATH}" | sudo tee "${LOG_FILE_PATH}" 2>&1
                fi
            fi
        fi
    fi
    #status
}

function status() {
    if is_vpn_running; then
        printf "%b" "${SUCCESS}"
        printf "Connected ...\n"
    else
        printf "%b" "${PRIMARY}"
        printf "Not connected ...\n"
    fi
    print_current_ip_address
    printf "%b" "${RESET}"
}

function stop() {

    if is_vpn_running; then
        printf "%b" "${WARNING}"
        printf "Connected ...\nRemoving %s ...\n" "${PID_FILE_PATH}"
        printf "%b" "${RESET}"
        local pid
        pid=$(cat "${PID_FILE_PATH}")
        kill -9 "${pid}" >/dev/null 2>&1
        rm -f "${PID_FILE_PATH}" >/dev/null 2>&1
        printf "%b" "${SUCCESS}"
        printf "Disconnected ...\n"
    else
        printf "%b" "${PRIMARY}"
        printf "Disconnected ...\n"
    fi

    print_current_ip_address
    printf "%b" "${RESET}"
}

function print_info() {

    printf "%b" "${WARNING}"
    printf "Usage: %s (start|stop|status|restart)\n" "$(basename "$0")"
    printf "%b" "${RESET}"

}

function is_network_available() {
    ping -q -c 1 -W 1 8.8.8.8 >/dev/null 2>&1
}

function is_vpn_running() {
    test -f "${PID_FILE_PATH}" && return 0
}

function print_current_ip_address() {
    local ip
    ip=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com)
    printf "Your IP address is %s ...\n" "${ip}"
}

function does_configuration_file_exist () {
    test -f $CONFIGURATION_FILE && return 0
}

function does_profiles_file_exist () {
    test -f $PROFILES_FILE && return 0
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
