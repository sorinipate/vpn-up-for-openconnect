#!/bin/bash

# Author: Sorin-Doru Ipate (@sorinipate)
# Edited by: Mohammad Amin Dadgar (@amindadgar)
# Edited by: Shunsuke Kitada (@shunk031)
# Copyright (c) Sorin-Doru Ipate

PROGRAM_NAME=$(basename "$0")
PROGRAM_PATH=$(dirname "$0")

CONFIGURATION_FILE="${PROGRAM_PATH}/config/${PROGRAM_NAME}.config"
PROFILES_FILE="${PROGRAM_PATH}/config/${PROGRAM_NAME}.profiles"

# Function to ensure the logs directory and log file exists and are writable
ensure_logs_directory_and_file_exists() {
    local logs_dir="${PROGRAM_PATH}/logs"
    local log_file="${logs_dir}/${PROGRAM_NAME}.log"

    # Check and create logs directory if it doesn't exist
    if [ ! -d "$logs_dir" ]; then
        echo "Logs directory not found. Creating: $logs_dir"
        mkdir -p "$logs_dir"
        if [ $? -ne 0 ]; then
            echo "Failed to create logs directory. Please check permissions."
            exit 1
        fi
        # Optionally, set specific permissions on logs directory
        chmod 755 "$logs_dir"
    fi

    # Check if log file exists and is writable, create if it doesn't exist
    if [ ! -f "$log_file" ]; then
        echo "Log file not found. Creating: $log_file"
        touch "$log_file"
        if [ $? -ne 0 ]; then
            echo "Failed to create log file. Please check permissions."
            exit 1
        fi
    fi

    # Ensure the log file is writable
    if [ ! -w "$log_file" ]; then
        echo "Log file is not writable. Setting permissions."
        chmod 644 "$log_file"
        if [ $? -ne 0 ]; then
            echo "Failed to set permissions on log file. Please check permissions."
            exit 1
        fi
    fi
}

PID_FILE_PATH="${PROGRAM_PATH}/logs/${PROGRAM_NAME}.pid"
LOG_FILE_PATH="${PROGRAM_PATH}/logs/${PROGRAM_NAME}.log"

ensure_logs_directory_and_file_exists

# Function to install Homebrew
install_homebrew() {
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    if [ $? -ne 0 ]; then
        echo "Failed to install Homebrew."
        return 1
    fi
}

# Function to install dependencies
install_dependencies() {
    local dependencies=("xmlstarlet" "openconnect")

    echo "Attempting to install missing dependencies..."
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            if [[ "$OSTYPE" == "linux-gnu"* ]]; then
                sudo apt-get install -y "$dep" || sudo yum install -y "$dep" || sudo dnf install -y "$dep"
            elif [[ "$OSTYPE" == "darwin"* ]]; then
                # Check if Homebrew is installed
                if ! command -v brew &> /dev/null; then
                    echo "Homebrew is not installed."
                    read -p "Do you want to install Homebrew? (y/n) " choice
                    case "$choice" in 
                        y|Y ) install_homebrew;;
                        n|N ) echo "Please install Homebrew manually and rerun this script."; return 1;;
                        * ) echo "Invalid response."; return 1;;
                    esac
                fi
                brew install "$dep"
            fi
        fi
    done
}

# Check for required commands and offer to install missing dependencies
for cmd in basename dirname printf echo kill test sudo xmlstarlet ping dig openconnect; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Required command '$cmd' is not installed."
        read -p "Do you want to try installing the missing dependencies? (y/n) " choice
        case "$choice" in 
            y|Y ) install_dependencies; break;;
            n|N ) echo "Exiting script. Please install the missing dependencies and try again."; exit 1;;
            * ) echo "Invalid response."; exit 1;;
        esac
    fi
done

# Utility function for printing success messages
print_success() {
    printf "%b" "${SUCCESS}"
    printf "%s\n" "$1"
    printf "%b" "${RESET}"
}

# Utility function for printing warning messages
print_warning() {
    printf "%b" "${WARNING}"
    printf "%s\n" "$1"
    printf "%b" "${RESET}"
}

# Utility function for printing danger/error messages
print_danger() {
    printf "%b" "${DANGER}"
    printf "%s\n" "$1"
    printf "%b" "${RESET}"
}

# Utility function for printing primary/information messages
print_primary() {
    printf "%b" "${PRIMARY}"
    printf "%s\n" "$1"
    printf "%b" "${RESET}"
}

# Function to check file existence
function check_file_existence() {
    local file_path="$1"
    local file_name="$2"
    if [ ! -f "$file_path" ]; then
        printf "%b%s file missing! \n%b" "${DANGER}" "$file_name" "${RESET}"
        exit 1
    fi
}

# Function to run openconnect with different parameters
function run_openconnect() {
    local background_flag=""
    local quiet_flag=""
    local server_cert_flag=""

    [ "$BACKGROUND" = TRUE ] && background_flag="--background"
    [ "$QUIET" = TRUE ] && quiet_flag="-q"
    [ -n "$SERVER_CERTIFICATE" ] && server_cert_flag="--servercert=\"$SERVER_CERTIFICATE\""

    local vpn_pass_pipe_cmd="echo $VPN_PASSWD"
    
    # Handle Duo 2FA method if required
    if [ "$VPN_DUO2FAMETHOD" = "passcode" ]; then
        read -p "Enter your Duo passcode: " duo_passcode
        vpn_pass_pipe_cmd="{ echo $VPN_PASSWD; sleep 1; echo $duo_passcode; }"
    elif [ "$VPN_DUO2FAMETHOD_DESCRIPTION" = "Not required" ]; then
        # If 2FA is not required, proceed without additional input
        vpn_pass_pipe_cmd="echo $VPN_PASSWD"
    elif [ -n "$VPN_DUO2FAMETHOD" ]; then
        vpn_pass_pipe_cmd="{ echo $VPN_PASSWD; sleep 1; echo $VPN_DUO2FAMETHOD; }"
    fi

    # Before attempting to write to the log file
    if [ ! -w "$LOG_FILE_PATH" ]; then
        echo "Cannot write to log file: $LOG_FILE_PATH. Please check permissions."
        exit 1
    fi

    # Start the VPN connection and run it in the background
    eval "$vpn_pass_pipe_cmd | sudo openconnect --protocol=\"$PROTOCOL\" $background_flag $quiet_flag \"$VPN_HOST\" --user=\"$VPN_USER\" --authgroup=\"$VPN_GROUP\" --passwd-on-stdin $server_cert_flag --pid-file \"$PID_FILE_PATH\" > \"$LOG_FILE_PATH\" 2>&1 &"

    local vpn_pid=$!
    sleep 5  # Give some time for the VPN process to initialize

    if kill -0 $vpn_pid 2> /dev/null; then
        echo "VPN connection process is running. Checking connection status..."
        return 0
    else
        echo "VPN process ended unexpectedly."
        return 1
    fi
}

# Function to set protocol description
function set_protocol_description() {
    case $PROTOCOL in
    "anyconnect") PROTOCOL_DESCRIPTION="Cisco AnyConnect SSL VPN" ;;
    "nc") PROTOCOL_DESCRIPTION="Juniper Network Connect" ;;
    "gp") PROTOCOL_DESCRIPTION="Palo Alto Networks (PAN) GlobalProtect SSL VPN" ;;
    "pulse") PROTOCOL_DESCRIPTION="Pulse Connect Secure SSL VPN" ;;
    *)
        printf "%bUnsupported protocol! Update the variable 'PROTOCOL' declaration in ${PROFILES_FILE} ...%b" "${DANGER}" "${RESET}"
        return
        ;;
    esac
}

# Function to set 2FA method description
function set_2fa_method_description() {
    if [ -z "$VPN_DUO2FAMETHOD" ]; then
        # If VPN_DUO2FAMETHOD is empty or not set, consider 2FA not required
        VPN_DUO2FAMETHOD_DESCRIPTION="Not required"
    else
        case $VPN_DUO2FAMETHOD in
        "push") VPN_DUO2FAMETHOD_DESCRIPTION="PUSH" ;;
        "phone") VPN_DUO2FAMETHOD_DESCRIPTION="PHONE" ;;
        "sms") VPN_DUO2FAMETHOD_DESCRIPTION="SMS" ;;
        "passcode")
            VPN_DUO2FAMETHOD_DESCRIPTION="PASSCODE (to be entered interactively)"
            ;;
        *) 
            printf "%bUnsupported 2FA method! Update the variable 'VPN_DUO2FAMETHOD' declaration in ${PROFILES_FILE} ...%b" "${DANGER}" "${RESET}"
            return
            ;;
        esac
    fi
}

function start() {
    # Check if configuration file exists
    check_file_existence "$CONFIGURATION_FILE" "Configuration"
    source $CONFIGURATION_FILE
    print_warning "Loaded configuration from $CONFIGURATION_FILE ..."

    # Check if profiles file exists
    check_file_existence "$PROFILES_FILE" "Profiles"
    IFS=$'\n' read -d '' -r -a vpn_names < <(xmlstarlet sel -t -m "//VPN" -v "name" -n $PROFILES_FILE)
    vpn_names+=("Quit")

    # Check network availability
    if ! is_network_available; then
        print_danger "Please check your internet connection or try again later!"
        exit 1
    fi

    # Check if VPN is already running
    if is_vpn_running; then
        print_warning "Already connected to a VPN!"
        exit 1
    fi

    # Check for SUDO usage and password
    if [ "$SUDO" = TRUE ]; then
        if [[ -z $SUDO_PASSWORD ]]; then
            print_danger "Variable 'SUDO_PASSWORD' is not declared! Update the variable 'SUDO_PASSWORD' declaration in ${CONFIGURATION_FILE} ..."
            return
        else
            echo "${SUDO_PASSWORD}" | sudo -S echo "Running as root ..."
        fi
    else
        print_warning "Running as normal user! OpenConnect requires to be executed with root privileges; please enter the root password when prompted..."
    fi

    # VPN Selection and Connection
    print_primary "Starting ${PROGRAM_NAME} ..."

    print_warning "Process ID (PID) stored in ${PID_FILE_PATH} ..."
    
    print_warning "Logs file (LOG) stored in ${LOG_FILE_PATH} ..."
    
    print_primary "Which VPN do you want to connect to?"
    
    select option in "${vpn_names[@]}"; do
        if [[ $option == "Quit" ]]; then
            print_warning "You chose to close the app!"
            exit
        elif [[ " ${vpn_names[@]} " =~ " ${option} " ]]; then
            IFS=$'\n' read -r -d '' VPN_NAME PROTOCOL VPN_HOST VPN_GROUP VPN_USER VPN_PASSWD VPN_DUO2FAMETHOD SERVER_CERTIFICATE < <(xmlstarlet sel -t -m "//VPN[name='$option']" -v "name" -o $'\n' -v "protocol" -o $'\n' -v "host" -o $'\n' -v "authGroup" -o $'\n' -v "user" -o $'\n' -v "password" -o $'\n' -v "duo2FAMethod" -o $'\n' -v "serverCertificate" -n $PROFILES_FILE)

            export VPN_NAME PROTOCOL VPN_HOST VPN_GROUP VPN_USER VPN_PASSWD VPN_DUO2FAMETHOD SERVER_CERTIFICATE
            connect
            break
        else
            print_danger "Invalid option! Please choose one of the options above..."
        fi
    done

#    # Post-connection checks
#    if is_vpn_running; then
#        print_success "Connected to ${VPN_NAME}"
#        print_current_ip_address
#    else
#        print_danger "Failed to connect!"
#    fi
}

function connect() {
    # Check if required variables are declared
    if [[ -z "${VPN_HOST}" ]]; then
        print_danger "Variable 'VPN_HOST' is not declared! Update the variable 'VPN_HOST' declaration in ${PROFILES_FILE} ..."
        return
    fi

    if [[ -z $PROTOCOL ]]; then
        print_danger "Variable 'PROTOCOL' is not declared! Update the variable 'PROTOCOL' declaration in ${PROFILES_FILE} ..."
        return
    fi

    # Set protocol description
    set_protocol_description

    # Set 2FA method description
    set_2fa_method_description

    # Display connection information
    print_primary "Starting the ${VPN_NAME} on ${VPN_HOST} using ${PROTOCOL_DESCRIPTION} ..."

    # Check and display 2FA information
    if [ -z "$VPN_DUO2FAMETHOD" ]; then
        print_warning "Connecting without 2FA (${VPN_DUO2FAMETHOD_DESCRIPTION}) ..."
    else
        print_primary "Connecting with Two-Factor Authentication (2FA) from Duo (${VPN_DUO2FAMETHOD_DESCRIPTION}) ..."
    fi

    # Call the function to run openconnect
    run_openconnect

    if [ $? -eq 0 ]; then
        # Add a delay to allow network changes to take effect
        sleep 10

    # Check the connection status and print success message
    if is_vpn_running; then
        print_success "Connected to ${VPN_NAME}"
    else
        print_danger "Failed to connect!"
    fi
    else
    print_danger "Failed to initiate VPN connection!"
    fi
}

function status() {
    if is_vpn_running; then
        print_success "Connected ..."
    else
        print_primary "Not connected ..."
    fi
    print_current_ip_address
}

function stop() {

    if is_vpn_running; then
        print_warning "Connected ... Removing ${PID_FILE_PATH} ..."
        local pid
        pid=$(cat "${PID_FILE_PATH}")
        kill -9 "${pid}" >/dev/null 2>&1
        rm -f "${PID_FILE_PATH}" >/dev/null 2>&1
        print_success "Disconnected ..."
    else
        print_success "Disconnected ..."
    fi

    print_current_ip_address
}

function print_info() {

    print_warning "Usage: %s (start|stop|status|restart)\n" "$(basename "$0")"

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

function does_configuration_file_exist() {
    test -f $CONFIGURATION_FILE && return 0
}

function does_profiles_file_exist() {
    test -f $PROFILES_FILE && return 0
}

# Case statement for handling script arguments
case "$1" in
start) start ;;
stop) stop ;;
status) status ;;
restart)
    $0 stop
    $0 start
    ;;
*)
    print_info
    exit 0
    ;;
esac
