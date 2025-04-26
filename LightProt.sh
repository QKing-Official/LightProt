#!/bin/bash

# Network DDoS Protection Script with Whitelist/Blocklist Support
# Compatible with Linux and WSL (with caveats)
# Version: 2.0
# ----------------------------------------------------

# ANSI color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Configuration ---
CONFIG_DIR="/etc/ddos-protection"
CONFIG_FILE="$CONFIG_DIR/ddos.conf"
WHITELIST_FILE="$CONFIG_DIR/whitelist.conf"
BLACKLIST_FILE="$CONFIG_DIR/blacklist.conf"
LOG_FILE="/var/log/ddos-protection.log"
STATUS_FILE="$CONFIG_DIR/protection_status"
RULES_FILE_V4="$CONFIG_DIR/iptables.rules"
RULES_FILE_V6="$CONFIG_DIR/ip6tables.rules"
PERSISTENCE_SCRIPT="$CONFIG_DIR/load-rules.sh"

# --- Default Settings (will be overridden by config file if it exists) ---
declare -A SETTINGS
SETTINGS=(
    ["CONN_LIMIT"]="80"
    ["CONN_BURST"]="100" # Not currently used in favor of overall limit, kept for potential future use
    ["SYN_LIMIT"]="2/s"
    ["SYN_BURST"]="4"
    ["ICMP_LIMIT"]="2/s"
    ["RST_LIMIT"]="5/s"
    ["SSH_PORT"]="22"
    ["SSH_CONN_LIMIT"]="4"
    ["SSH_CONN_SECONDS"]="60"
    ["HTTP_PORT"]="80"
    ["HTTP_CONN_LIMIT"]="50"
    ["HTTPS_PORT"]="443"
    ["HTTPS_CONN_LIMIT"]="50"
    ["DNS_UDP_PORT"]="53"
    ["DNS_TCP_PORT"]="53"
    ["UDP_LIMIT"]="15/s"
    ["UDP_BURST"]="30"
    ["ALLOWED_UDP_PORTS"]="53,67,68,123" # DNS, DHCP, NTP by default
    ["ENABLE_SYN_PROTECTION"]="true"
    ["ENABLE_ICMP_PROTECTION"]="true"
    ["ENABLE_PORT_SCAN_PROTECTION"]="true"
    ["ENABLE_HTTP_HTTPS_PROTECTION"]="true"
    ["ENABLE_SSH_PROTECTION"]="true"
    ["ENABLE_UDP_PROTECTION"]="true"
    ["ENABLE_CONNTRACK_OPTIMIZATION"]="true"
    ["ENABLE_RP_FILTER"]="true"
    ["ENABLE_RST_PROTECTION"]="true"
    ["LOG_BLOCKED_PACKETS"]="false" # Set to true to log dropped packets (can be verbose)
)

# --- Script Logic ---

# Function to log messages
log_message() {
    local message="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
    echo -e "$message" # Also print to console
}

# Check if script is running with root privileges
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}This script must be run as root. Please use sudo.${NC}" >&2
        exit 1
    fi
}

# Function to check for required commands
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log_message "${YELLOW}Command '$cmd' not found. Attempting to install prerequisites...${NC}"
        install_prerequisites
        if ! command -v "$cmd" &> /dev/null; then
            log_message "${RED}Failed to install or find '$cmd'. Please install it manually.${NC}"
            exit 1
        fi
    fi
}

# Install necessary packages
install_prerequisites() {
    log_message "${BLUE}Checking and installing prerequisites...${NC}"
    local packages_to_install=()
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        command -v iptables &> /dev/null || packages_to_install+=("iptables")
        command -v ip6tables &> /dev/null || packages_to_install+=("iptables") # Usually included
        command -v iptables-save &> /dev/null || packages_to_install+=("iptables")
        command -v iptables-restore &> /dev/null || packages_to_install+=("iptables")
        command -v modprobe &> /dev/null || packages_to_install+=("kmod")
        command -v sysctl &> /dev/null || packages_to_install+=("procps")
        # Check persistence package
        dpkg -l | grep -q iptables-persistent || packages_to_install+=("iptables-persistent")

        if [ ${#packages_to_install[@]} -gt 0 ]; then
            log_message "${YELLOW}Installing: ${packages_to_install[*]}${NC}"
            DEBIAN_FRONTEND=noninteractive apt-get update -y || log_message "${RED}apt update failed${NC}"
            DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages_to_install[@]}" || log_message "${RED}apt install failed${NC}"
        fi

    elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
        # RHEL/CentOS/Fedora
        local pkg_manager="yum"
        command -v dnf &> /dev/null && pkg_manager="dnf"

        command -v iptables &> /dev/null || packages_to_install+=("iptables")
        command -v ip6tables &> /dev/null || packages_to_install+=("iptables-ipv6") # Separate package often
        command -v iptables-save &> /dev/null || packages_to_install+=("iptables-services")
        command -v iptables-restore &> /dev/null || packages_to_install+=("iptables-services")
        command -v modprobe &> /dev/null || packages_to_install+=("kmod")
        command -v sysctl &> /dev/null || packages_to_install+=("procps-ng")

        if [ ${#packages_to_install[@]} -gt 0 ]; then
             log_message "${YELLOW}Installing: ${packages_to_install[*]}${NC}"
            "$pkg_manager" install -y "${packages_to_install[@]}" || log_message "${RED}$pkg_manager install failed${NC}"
        fi
        # Enable services for persistence
         systemctl enable iptables.service 2>/dev/null
         systemctl enable ip6tables.service 2>/dev/null

    else
        log_message "${RED}Unsupported package manager. Please install iptables, ip6tables, and persistence tools manually.${NC}"
        # Cannot guarantee prerequisites, continue cautiously
    fi

    # Ensure modules needed by rules are loaded
    local modules=("nf_conntrack" "ipt_recent" "xt_limit" "xt_connlimit" "xt_comment" "xt_state")
    log_message "${BLUE}Checking kernel modules...${NC}"
    for module in "${modules[@]}"; do
        if ! lsmod | grep -q "^${module}"; then
            log_message "${YELLOW}Loading kernel module: $module${NC}"
            modprobe "$module"
            if ! lsmod | grep -q "^${module}"; then
                 log_message "${YELLOW}Warning: Failed to load kernel module $module. Some rules may not work.${NC}"
            fi
        fi
    done
}

# Create configuration directory and files if they don't exist
# Create configuration directory and files if they don't exist
initialize_config() {
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    if [ ! -f "$CONFIG_FILE" ]; then
        log_message "${YELLOW}Configuration file not found. Creating default: $CONFIG_FILE${NC}"
        echo "# DDoS Protection Configuration" > "$CONFIG_FILE"
        echo "# Version: 2.0" >> "$CONFIG_FILE"
        echo "# --- Limits and Settings ---" >> "$CONFIG_FILE"
        # Use print statement to handle values correctly, especially booleans
        printf "%s=%s\n" \
            "CONN_LIMIT" "${SETTINGS[CONN_LIMIT]}" \
            "CONN_BURST" "${SETTINGS[CONN_BURST]}" \
            "SYN_LIMIT" "${SETTINGS[SYN_LIMIT]}" \
            "SYN_BURST" "${SETTINGS[SYN_BURST]}" \
            "ICMP_LIMIT" "${SETTINGS[ICMP_LIMIT]}" \
            "RST_LIMIT" "${SETTINGS[RST_LIMIT]}" \
            "SSH_PORT" "${SETTINGS[SSH_PORT]}" \
            "SSH_CONN_LIMIT" "${SETTINGS[SSH_CONN_LIMIT]}" \
            "SSH_CONN_SECONDS" "${SETTINGS[SSH_CONN_SECONDS]}" \
            "HTTP_PORT" "${SETTINGS[HTTP_PORT]}" \
            "HTTP_CONN_LIMIT" "${SETTINGS[HTTP_CONN_LIMIT]}" \
            "HTTPS_PORT" "${SETTINGS[HTTPS_PORT]}" \
            "HTTPS_CONN_LIMIT" "${SETTINGS[HTTPS_CONN_LIMIT]}" \
            "DNS_UDP_PORT" "${SETTINGS[DNS_UDP_PORT]}" \
            "DNS_TCP_PORT" "${SETTINGS[DNS_TCP_PORT]}" \
            "UDP_LIMIT" "${SETTINGS[UDP_LIMIT]}" \
            "UDP_BURST" "${SETTINGS[UDP_BURST]}" \
            >> "$CONFIG_FILE"

        echo "" >> "$CONFIG_FILE"
        echo "# --- Allowed UDP ports (comma separated) ---" >> "$CONFIG_FILE"
        echo "ALLOWED_UDP_PORTS=${SETTINGS[ALLOWED_UDP_PORTS]}" >> "$CONFIG_FILE"
        echo "" >> "$CONFIG_FILE"
        echo "# --- Enable specific protection modules (true/false) ---" >> "$CONFIG_FILE"
        printf "%s=%s\n" \
            "ENABLE_SYN_PROTECTION" "${SETTINGS[ENABLE_SYN_PROTECTION]}" \
            "ENABLE_ICMP_PROTECTION" "${SETTINGS[ENABLE_ICMP_PROTECTION]}" \
            "ENABLE_PORT_SCAN_PROTECTION" "${SETTINGS[ENABLE_PORT_SCAN_PROTECTION]}" \
            "ENABLE_HTTP_HTTPS_PROTECTION" "${SETTINGS[ENABLE_HTTP_HTTPS_PROTECTION]}" \
            "ENABLE_SSH_PROTECTION" "${SETTINGS[ENABLE_SSH_PROTECTION]}" \
            "ENABLE_UDP_PROTECTION" "${SETTINGS[ENABLE_UDP_PROTECTION]}" \
            "ENABLE_CONNTRACK_OPTIMIZATION" "${SETTINGS[ENABLE_CONNTRACK_OPTIMIZATION]}" \
            "ENABLE_RP_FILTER" "${SETTINGS[ENABLE_RP_FILTER]}" \
            "ENABLE_RST_PROTECTION" "${SETTINGS[ENABLE_RST_PROTECTION]}" \
             >> "$CONFIG_FILE"

        echo "" >> "$CONFIG_FILE"
        echo "# --- Log dropped packets (true/false) - Warning: Can be very verbose ---" >> "$CONFIG_FILE"
        echo "LOG_BLOCKED_PACKETS=${SETTINGS[LOG_BLOCKED_PACKETS]}" >> "$CONFIG_FILE"

        chmod 600 "$CONFIG_FILE"
    fi

    # Corrected file creation logic:
    if [ ! -f "$WHITELIST_FILE" ]; then
        log_message "${YELLOW}Creating default whitelist: $WHITELIST_FILE${NC}"
        echo "# Whitelist - IPs/CIDRs (one per line)" > "$WHITELIST_FILE"
        echo "127.0.0.1" >> "$WHITELIST_FILE"
        echo "::1" >> "$WHITELIST_FILE"
        chmod 600 "$WHITELIST_FILE"
    fi

    if [ ! -f "$BLACKLIST_FILE" ]; then
        log_message "${YELLOW}Creating default blacklist: $BLACKLIST_FILE${NC}"
        echo "# Blacklist - IPs/CIDRs (one per line)" > "$BLACKLIST_FILE"
        chmod 600 "$BLACKLIST_FILE"
    fi

    if [ ! -f "$STATUS_FILE" ]; then
        log_message "${YELLOW}Creating status file: $STATUS_FILE${NC}"
        echo "INACTIVE" > "$STATUS_FILE"
        chmod 644 "$STATUS_FILE"
    fi
}
# Load configuration from file
load_config() {
    log_message "${BLUE}Loading configuration from $CONFIG_FILE...${NC}"
    if [ -f "$CONFIG_FILE" ]; then
        # Read config file line by line, skipping comments and empty lines
        while IFS='=' read -r key value || [[ -n "$key" ]]; do
            # Remove leading/trailing whitespace and comments
            key=$(echo "$key" | sed 's/^[ \t]*//;s/[ \t]*#.*//;s/[ \t]*$//')
            value=$(echo "$value" | sed 's/^[ \t]*//;s/[ \t]*#.*//;s/[ \t]*$//')

            # Update SETTINGS if key is valid and value is not empty
            if [[ -n "$key" && -v "SETTINGS[$key]" && -n "$value" ]]; then
                SETTINGS["$key"]="$value"
                # log_message "Loaded: $key = $value" # Uncomment for debugging
            elif [[ -n "$key" && "$key" != \#* ]]; then
                 log_message "${YELLOW}Warning: Ignoring unknown or empty configuration key '$key' in $CONFIG_FILE${NC}"
            fi
        done < <(grep -v '^[[:space:]]*#' "$CONFIG_FILE" | grep '=') # Process only lines with '=' after removing comments
    else
        log_message "${YELLOW}Config file $CONFIG_FILE not found. Using default settings.${NC}"
    fi
}

# Function to manage IP lists (Whitelist/Blacklist)
manage_ip_list() {
    local list_file="$1"
    local list_name="$2" # "Whitelist" or "Blacklist"
    local action="$3"    # "add" or "remove"

    log_message "${BLUE}Managing $list_name ($list_file)...${NC}"
    if [ ! -f "$list_file" ]; then
        log_message "${RED}Error: $list_name file not found at $list_file${NC}"
        return 1
    fi

    # Display current list
    echo -e "${YELLOW}Current $list_name contents:${NC}"
    grep -v '^[[:space:]]*#' "$list_file" | grep -v '^[[:space:]]*$' || echo "(empty)"

    echo -e "${YELLOW}Would you like to $action IPs ${action^} the $list_name? (y/n)${NC}"
    read -r confirm_action
    if [[ ! "$confirm_action" =~ ^[Yy]$ ]]; then
        return 0
    fi

    while true; do
        echo -e "${YELLOW}Enter IP address or CIDR to $action (or 'done' to finish):${NC}"
        read -r ip_entry

        if [[ "$ip_entry" == "done" ]]; then
            break
        fi

        # Basic validation (allows IPv4, IPv6, CIDR)
        if ! echo "$ip_entry" | grep -Eq '^[0-9a-fA-F.:/]+$'; then
             echo -e "${RED}Invalid format. Please enter a valid IP or CIDR.${NC}"
             continue
        fi

        if [[ "$action" == "add" ]]; then
            if grep -qFx "$ip_entry" "$list_file"; then
                echo -e "${YELLOW}IP '$ip_entry' already in $list_name.${NC}"
            else
                echo "$ip_entry" >> "$list_file"
                echo -e "${GREEN}Added '$ip_entry' to $list_name.${NC}"
            fi
        elif [[ "$action" == "remove" ]]; then
            if grep -qFx "$ip_entry" "$list_file"; then
                # Use sed to remove the exact line match
                sed -i "\:^${ip_entry}\$:d" "$list_file"
                echo -e "${GREEN}Removed '$ip_entry' from $list_name.${NC}"
            else
                echo -e "${YELLOW}IP '$ip_entry' not found in $list_name.${NC}"
            fi
        fi
    done
    log_message "${GREEN}$list_name updated.${NC}"
}


# Helper function to apply a rule to both iptables and ip6tables if applicable
apply_rule() {
    local ipt_cmd="$1" # iptables or ip6tables
    shift
    local rule_args=("$@")
    local comment_added=false

    # Ensure a comment is present for easier identification
    for arg in "${rule_args[@]}"; do
        if [[ "$arg" == "--comment" ]]; then
            comment_added=true
            break
        fi
    done
    if ! $comment_added; then
        rule_args+=("-m" "comment" "--comment" "DDP-GenericRule") # Add a default comment
    fi

    if command -v "$ipt_cmd" &> /dev/null; then
        "$ipt_cmd" "${rule_args[@]}"
        if [ $? -ne 0 ]; then
            log_message "${YELLOW}Warning: Failed to apply $ipt_cmd rule: ${rule_args[*]}${NC}"
        fi
    else
         log_message "${YELLOW}Warning: Command $ipt_cmd not found, skipping rule: ${rule_args[*]}${NC}"
    fi
}

# Function to reset firewall rules
reset_firewall() {
    log_message "${BLUE}Resetting firewall rules (flushing all chains)...${NC}"
    apply_rule iptables -F
    apply_rule iptables -X
    apply_rule iptables -t nat -F
    apply_rule iptables -t nat -X
    apply_rule iptables -t mangle -F
    apply_rule iptables -t mangle -X
    apply_rule ip6tables -F
    apply_rule ip6tables -X
    apply_rule ip6tables -t mangle -F
    apply_rule ip6tables -t mangle -X

    # Set default policies to DROP (safer starting point)
    apply_rule iptables -P INPUT DROP
    apply_rule iptables -P FORWARD DROP
    apply_rule iptables -P OUTPUT ACCEPT # Allow outgoing connections by default
    apply_rule ip6tables -P INPUT DROP
    apply_rule ip6tables -P FORWARD DROP
    apply_rule ip6tables -P OUTPUT ACCEPT

    log_message "${GREEN}Firewall rules reset to default DROP policy.${NC}"
}

# Function to apply basic setup and list rules
setup_base_rules() {
    log_message "${BLUE}Applying base firewall rules (loopback, established, lists)...${NC}"

    # Allow loopback traffic
    apply_rule iptables -A INPUT -i lo -j ACCEPT -m comment --comment "DDP-AllowLoopback"
    apply_rule ip6tables -A INPUT -i lo -j ACCEPT -m comment --comment "DDP-AllowLoopback"
    # Output for loopback is already handled by default OUTPUT ACCEPT policy

    # Allow established and related connections (Essential!)
    apply_rule iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "DDP-AllowEstablished"
    apply_rule ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "DDP-AllowEstablished"

    # Apply Blocklist rules (applied first)
    log_message "${BLUE}Applying blocklist rules...${NC}"
    if [ -f "$BLACKLIST_FILE" ]; then
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            ip=$(echo "$ip" | sed 's/^[ \t]*//;s/[ \t]*#.*//;s/[ \t]*$//')
            [[ -z "$ip" ]] && continue
            if [[ "$ip" == *":"* ]]; then # IPv6
                 apply_rule ip6tables -A INPUT -s "$ip" -j DROP -m comment --comment "DDP-BlockedIP"
            else # IPv4
                 apply_rule iptables -A INPUT -s "$ip" -j DROP -m comment --comment "DDP-BlockedIP"
            fi
             log_message "${RED}Blocked: $ip${NC}"
        done < <(grep -v '^[[:space:]]*#' "$BLACKLIST_FILE")
    fi

    # Apply Whitelist rules
    log_message "${BLUE}Applying whitelist rules...${NC}"
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r ip || [[ -n "$ip" ]]; do
            ip=$(echo "$ip" | sed 's/^[ \t]*//;s/[ \t]*#.*//;s/[ \t]*$//')
            [[ -z "$ip" ]] && continue
            if [[ "$ip" == *":"* ]]; then # IPv6
                 apply_rule ip6tables -A INPUT -s "$ip" -j ACCEPT -m comment --comment "DDP-WhitelistedIP"
            else # IPv4
                 apply_rule iptables -A INPUT -s "$ip" -j ACCEPT -m comment --comment "DDP-WhitelistedIP"
            fi
             log_message "${GREEN}Whitelisted: $ip${NC}"
        done < <(grep -v '^[[:space:]]*#' "$WHITELIST_FILE")
    fi

    # Drop invalid packets (often used in scans/attacks)
    apply_rule iptables -A INPUT -m conntrack --ctstate INVALID -j DROP -m comment --comment "DDP-DropInvalid"
    apply_rule ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP -m comment --comment "DDP-DropInvalid"

    # Add a marker rule to easily check if protection is active (last rule in INPUT before service accepts)
    apply_rule iptables -A INPUT -p tcp --tcp-flags ALL ALL -m comment --comment "DDP-ACTIVE-MARKER" -j DROP
    apply_rule ip6tables -A INPUT -p tcp --tcp-flags ALL ALL -m comment --comment "DDP-ACTIVE-MARKER" -j DROP
}

# Function to apply logging for dropped packets if enabled
apply_drop_logging() {
    if [[ "${SETTINGS[LOG_BLOCKED_PACKETS],,}" == "true" ]]; then
        log_message "${YELLOW}Enabling logging for dropped packets (can be verbose)...${NC}"
        # Insert logging rules just before the final default DROP policy actions
        # These rules match packets that would otherwise be dropped by the default policy
        apply_rule iptables -A INPUT -m limit --limit 2/min -j LOG --log-prefix "DDP-Dropped: " --log-level 7
        apply_rule ip6tables -A INPUT -m limit --limit 2/min -j LOG --log-prefix "DDP6-Dropped: " --log-level 7
        # Note: The actual DROP happens due to the default policy P INPUT DROP if no rule accepts the packet.
    fi
}


# --- Protection Modules ---

configure_sysctl() {
    log_message "${BLUE}Applying sysctl kernel parameter optimizations...${NC}"
    local setting_applied=false

    if [[ "${SETTINGS[ENABLE_RP_FILTER],,}" == "true" ]]; then
        # Enable Source Address Verification (helps against IP spoofing)
        if sysctl -w net.ipv4.conf.default.rp_filter=1 && sysctl -w net.ipv4.conf.all.rp_filter=1; then
            log_message "${GREEN}Enabled Reverse Path Filtering (rp_filter)${NC}"
            setting_applied=true
        else
            log_message "${YELLOW}Warning: Failed to apply rp_filter sysctl settings.${NC}"
        fi
    fi

    if [[ "${SETTINGS[ENABLE_SYN_PROTECTION],,}" == "true" ]]; then
        # Enable TCP SYN Cookies (helps against SYN floods when backlog is full)
        if sysctl -w net.ipv4.tcp_syncookies=1; then
            log_message "${GREEN}Enabled TCP SYN Cookies${NC}"
            setting_applied=true
        else
            log_message "${YELLOW}Warning: Failed to enable TCP SYN Cookies.${NC}"
        fi
        # Increase SYN backlog queue size
        if sysctl -w net.ipv4.tcp_max_syn_backlog=2048; then
             log_message "${GREEN}Set tcp_max_syn_backlog=2048${NC}"
             setting_applied=true
        else
             log_message "${YELLOW}Warning: Failed to set tcp_max_syn_backlog.${NC}"
        fi
         # Reduce SYN-ACK retries
        if sysctl -w net.ipv4.tcp_synack_retries=1; then
             log_message "${GREEN}Set tcp_synack_retries=1${NC}"
             setting_applied=true
        else
             log_message "${YELLOW}Warning: Failed to set tcp_synack_retries.${NC}"
        fi
    fi

    if [[ "${SETTINGS[ENABLE_CONNTRACK_OPTIMIZATION],,}" == "true" ]]; then
        # Configure connection tracking (if module is available)
        if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
            if sysctl -w net.netfilter.nf_conntrack_max=1000000; then log_message "${GREEN}Set nf_conntrack_max=1000000${NC}"; setting_applied=true; fi
            if sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=1800; then log_message "${GREEN}Set nf_conntrack_tcp_timeout_established=1800${NC}"; setting_applied=true; fi
            # Shorten timeouts for states common during attacks
            if sysctl -w net.netfilter.nf_conntrack_tcp_timeout_syn_recv=30; then log_message "${GREEN}Set nf_conntrack_tcp_timeout_syn_recv=30${NC}"; setting_applied=true; fi
            if sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=60; then log_message "${GREEN}Set nf_conntrack_tcp_timeout_time_wait=60${NC}"; setting_applied=true; fi
            if sysctl -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=60; then log_message "${GREEN}Set nf_conntrack_tcp_timeout_fin_wait=60${NC}"; setting_applied=true; fi
            if sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=60; then log_message "${GREEN}Set nf_conntrack_tcp_timeout_close_wait=60${NC}"; setting_applied=true; fi
            echo "1" > "$CONFIG_DIR/conntrack_optimized"
        else
             log_message "${YELLOW}nf_conntrack sysctl parameters not found. Skipping conntrack optimization.${NC}"
             echo "0" > "$CONFIG_DIR/conntrack_optimized"
        fi
    else
        echo "0" > "$CONFIG_DIR/conntrack_optimized"
    fi

    if $setting_applied; then
        # Optionally make sysctl settings persistent across reboots
        # This depends on the system's method (e.g., /etc/sysctl.conf, /etc/sysctl.d/)
        # We'll add it to the load-rules script instead for simplicity here.
        log_message "${GREEN}Sysctl settings applied. Add to /etc/sysctl.conf or similar for boot persistence.${NC}"
    fi
}

protect_syn_flood() {
    if [[ "${SETTINGS[ENABLE_SYN_PROTECTION],,}" == "true" ]]; then
        log_message "${BLUE}Applying SYN Flood protection...${NC}"
        local limit="${SETTINGS[SYN_LIMIT]}"
        local burst="${SETTINGS[SYN_BURST]}"
        # Limit NEW incoming SYN packets aggressively
        apply_rule iptables -A INPUT -p tcp --syn -m limit --limit "$limit" --limit-burst "$burst" -j ACCEPT -m comment --comment "DDP-SYN-Limit"
        apply_rule ip6tables -A INPUT -p tcp --syn -m limit --limit "$limit" --limit-burst "$burst" -j ACCEPT -m comment --comment "DDP-SYN-Limit"
        apply_rule iptables -A INPUT -p tcp --syn -j DROP -m comment --comment "DDP-DropSYN"
        apply_rule ip6tables -A INPUT -p tcp --syn -j DROP -m comment --comment "DDP-DropSYN"
        log_message "${GREEN}SYN Flood protection enabled (Limit: $limit, Burst: $burst).${NC}"
    else
        log_message "${YELLOW}SYN Flood protection disabled by configuration.${NC}"
    fi
}

protect_icmp() {
    if [[ "${SETTINGS[ENABLE_ICMP_PROTECTION],,}" == "true" ]]; then
        log_message "${BLUE}Applying ICMP (Ping) Flood protection...${NC}"
        local limit="${SETTINGS[ICMP_LIMIT]}"
        # Limit ICMP echo requests (ping)
        apply_rule iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit "$limit" -j ACCEPT -m comment --comment "DDP-ICMP-Limit"
        apply_rule ip6tables -A INPUT -p icmpv6 --icmpv6-type 128 -m limit --limit "$limit" -j ACCEPT -m comment --comment "DDP-ICMPv6-Limit"
        apply_rule iptables -A INPUT -p icmp --icmp-type 8 -j DROP -m comment --comment "DDP-DropICMP"
        apply_rule ip6tables -A INPUT -p icmpv6 --icmpv6-type 128 -j DROP -m comment --comment "DDP-DropICMPv6"

        # Block fragmented packets (can be used in attacks)
        apply_rule iptables -A INPUT -f -j DROP -m comment --comment "DDP-DropFragmented"
        # Note: IPv6 handles fragmentation differently, often less of an issue at this layer

        log_message "${GREEN}ICMP Flood protection enabled (Limit: $limit). Fragmented packets dropped.${NC}"
    else
        log_message "${YELLOW}ICMP protection disabled by configuration.${NC}"
    fi
}

protect_port_scan() {
    if [[ "${SETTINGS[ENABLE_PORT_SCAN_PROTECTION],,}" == "true" ]]; then
        log_message "${BLUE}Applying Port Scan protection...${NC}"
        # Block various scan types by looking at TCP flags
        apply_rule iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP -m comment --comment "DDP-DropNullScan"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP -m comment --comment "DDP-DropNullScan"

        apply_rule iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP -m comment --comment "DDP-DropSynFinScan"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP -m comment --comment "DDP-DropSynFinScan"

        apply_rule iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP -m comment --comment "DDP-DropSynRstScan"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP -m comment --comment "DDP-DropSynRstScan"

        apply_rule iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP -m comment --comment "DDP-DropFinRstScan"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP -m comment --comment "DDP-DropFinRstScan"

        apply_rule iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP -m comment --comment "DDP-DropAckFinScan"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP -m comment --comment "DDP-DropAckFinScan"

        apply_rule iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP -m comment --comment "DDP-DropAckUrgScan"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP -m comment --comment "DDP-DropAckUrgScan"

        apply_rule iptables -A INPUT -p tcp --tcp-flags FIN FIN -m limit --limit 5/minute -j ACCEPT -m comment --comment "DDP-XmasFinLimit" # Limit stealth FIN scans
        apply_rule iptables -A INPUT -p tcp --tcp-flags FIN FIN -j DROP -m comment --comment "DDP-XmasFinDrop"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags FIN FIN -m limit --limit 5/minute -j ACCEPT -m comment --comment "DDP-XmasFinLimit"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags FIN FIN -j DROP -m comment --comment "DDP-XmasFinDrop"

        log_message "${GREEN}Port Scan protection enabled.${NC}"
    else
        log_message "${YELLOW}Port Scan protection disabled by configuration.${NC}"
    fi
}

protect_rst_flood() {
    if [[ "${SETTINGS[ENABLE_RST_PROTECTION],,}" == "true" ]]; then
        log_message "${BLUE}Applying TCP RST Flood protection...${NC}"
        local limit="${SETTINGS[RST_LIMIT]}"
        # Limit incoming RST packets
        apply_rule iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit "$limit" --limit-burst "${limit%/*}" -j ACCEPT -m comment --comment "DDP-RST-Limit"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit "$limit" --limit-burst "${limit%/*}" -j ACCEPT -m comment --comment "DDP-RST-Limit"
        apply_rule iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP -m comment --comment "DDP-DropRST"
        apply_rule ip6tables -A INPUT -p tcp --tcp-flags RST RST -j DROP -m comment --comment "DDP-DropRST"
        log_message "${GREEN}TCP RST Flood protection enabled (Limit: $limit).${NC}"
    else
        log_message "${YELLOW}TCP RST Flood protection disabled by configuration.${NC}"
    fi
}


protect_slow_http() {
    if [[ "${SETTINGS[ENABLE_HTTP_HTTPS_PROTECTION],,}" == "true" ]]; then
        log_message "${BLUE}Applying Slow HTTP/DoS protection (connection limits)...${NC}"
        local http_port="${SETTINGS[HTTP_PORT]}"
        local https_port="${SETTINGS[HTTPS_PORT]}"
        local http_limit="${SETTINGS[HTTP_CONN_LIMIT]}"
        local https_limit="${SETTINGS[HTTPS_CONN_LIMIT]}"
        local overall_limit="${SETTINGS[CONN_LIMIT]}" # Overall limit per IP

        # Limit overall connections per source IP to mitigate various floods
        # Using connlimit requires nf_conntrack and xt_connlimit modules
        apply_rule iptables -A INPUT -p tcp -m connlimit --connlimit-above "$overall_limit" --connlimit-mask 32 -j DROP -m comment --comment "DDP-OverallConnLimit"
        apply_rule ip6tables -A INPUT -p tcp -m connlimit --connlimit-above "$overall_limit" --connlimit-mask 128 -j DROP -m comment --comment "DDP-OverallConnLimit"

        # Limit connections specifically to HTTP/HTTPS ports (can be more specific than overall)
        if [[ "$http_port" =~ ^[0-9]+$ && "$http_limit" =~ ^[0-9]+$ && "$http_limit" -lt "$overall_limit" ]]; then
             apply_rule iptables -A INPUT -p tcp --syn --dport "$http_port" -m connlimit --connlimit-above "$http_limit" --connlimit-mask 32 -j DROP -m comment --comment "DDP-HTTPConnLimit"
             apply_rule ip6tables -A INPUT -p tcp --syn --dport "$http_port" -m connlimit --connlimit-above "$http_limit" --connlimit-mask 128 -j DROP -m comment --comment "DDP-HTTPConnLimit"
             log_message "${GREEN}HTTP connection limit enabled (Port: $http_port, Limit: $http_limit).${NC}"
        fi
        if [[ "$https_port" =~ ^[0-9]+$ && "$https_limit" =~ ^[0-9]+$ && "$https_limit" -lt "$overall_limit" ]]; then
             apply_rule iptables -A INPUT -p tcp --syn --dport "$https_port" -m connlimit --connlimit-above "$https_limit" --connlimit-mask 32 -j DROP -m comment --comment "DDP-HTTPSConnLimit"
             apply_rule ip6tables -A INPUT -p tcp --syn --dport "$https_port" -m connlimit --connlimit-above "$https_limit" --connlimit-mask 128 -j DROP -m comment --comment "DDP-HTTPSConnLimit"
             log_message "${GREEN}HTTPS connection limit enabled (Port: $https_port, Limit: $https_limit).${NC}"
        fi
         log_message "${GREEN}Overall connection limit per IP set to $overall_limit.${NC}"
    else
        log_message "${YELLOW}HTTP/HTTPS protection disabled by configuration.${NC}"
    fi
}

protect_udp_flood() {
    if [[ "${SETTINGS[ENABLE_UDP_PROTECTION],,}" == "true" ]]; then
        log_message "${BLUE}Applying UDP Flood protection...${NC}"
        local limit="${SETTINGS[UDP_LIMIT]}"
        local burst="${SETTINGS[UDP_BURST]}"
        local allowed_ports="${SETTINGS[ALLOWED_UDP_PORTS]}"

        # Create dedicated chains for UDP handling
        apply_rule iptables -N UDP-FILTER
        apply_rule ip6tables -N UDP6-FILTER
        apply_rule iptables -A INPUT -p udp -j UDP-FILTER
        apply_rule ip6tables -A INPUT -p udp -j UDP6-FILTER # Note: UDP uses INPUT chain for IPv6 too

        # Apply general UDP rate limiting
        apply_rule iptables -A UDP-FILTER -m limit --limit "$limit" --limit-burst "$burst" -j RETURN -m comment --comment "DDP-UDP-RateLimit"
        apply_rule ip6tables -A UDP6-FILTER -m limit --limit "$limit" --limit-burst "$burst" -j RETURN -m comment --comment "DDP-UDP6-RateLimit"
        apply_rule iptables -A UDP-FILTER -j DROP -m comment --comment "DDP-DropUDP-RateExceeded"
        apply_rule ip6tables -A UDP6-FILTER -j DROP -m comment --comment "DDP-DropUDP6-RateExceeded"

        # Allow specific UDP ports listed in config *before* the rate limit hits RETURN target (meaning they passed rate limit)
        if [[ -n "$allowed_ports" ]]; then
            IFS=',' read -ra ADDR <<< "$allowed_ports"
            for port in "${ADDR[@]}"; do
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    log_message "${GREEN}Allowing UDP port $port.${NC}"
                    # Insert ACCEPT rules at the beginning of the INPUT chain *after* base rules but *before* general UDP jump
                    apply_rule iptables -I INPUT 5 -p udp --dport "$port" -j ACCEPT -m comment --comment "DDP-AllowUDP-$port"
                    apply_rule ip6tables -I INPUT 5 -p udp --dport "$port" -j ACCEPT -m comment --comment "DDP-AllowUDP6-$port"
                fi
            done
        fi

        log_message "${GREEN}UDP Flood protection enabled (Rate Limit: $limit, Burst: $burst). Allowed Ports: $allowed_ports.${NC}"
    else
         log_message "${YELLOW}UDP protection disabled by configuration. All UDP traffic will be dropped by default policy unless explicitly allowed.${NC}"
         # We still need to allow specific UDP services like DNS if UDP protection is off, but they are needed.
         # This is handled in allow_common_services.
    fi
}


# --- Service Allowing ---

allow_common_services() {
    log_message "${BLUE}Applying rules to allow common services based on configuration...${NC}"

    # SSH Protection and Allowing
    if [[ "${SETTINGS[ENABLE_SSH_PROTECTION],,}" == "true" ]]; then
        local ssh_port="${SETTINGS[SSH_PORT]}"
        local ssh_limit="${SETTINGS[SSH_CONN_LIMIT]}"
        local ssh_seconds="${SETTINGS[SSH_CONN_SECONDS]}"
        if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then
             log_message "${GREEN}Allowing SSH on port $ssh_port with rate limiting (Limit: $ssh_limit per $ssh_seconds s).${NC}"
             # Use iptables 'recent' module for bruteforce protection
            apply_rule iptables -A INPUT -p tcp --dport "$ssh_port" -m conntrack --ctstate NEW -m recent --set --name SSH --rsource -m comment --comment "DDP-SSH-TrackIP"
            apply_rule ip6tables -A INPUT -p tcp --dport "$ssh_port" -m conntrack --ctstate NEW -m recent --set --name SSH6 --rsource -m comment --comment "DDP-SSH6-TrackIP"

            apply_rule iptables -A INPUT -p tcp --dport "$ssh_port" -m conntrack --ctstate NEW -m recent --update --seconds "$ssh_seconds" --hitcount "$ssh_limit" --name SSH --rsource -j DROP -m comment --comment "DDP-SSH-RateLimitDrop"
            apply_rule ip6tables -A INPUT -p tcp --dport "$ssh_port" -m conntrack --ctstate NEW -m recent --update --seconds "$ssh_seconds" --hitcount "$ssh_limit" --name SSH6 --rsource -j DROP -m comment --comment "DDP-SSH6-RateLimitDrop"

            # Allow the connection if it passes the rate limit
            apply_rule iptables -A INPUT -p tcp --dport "$ssh_port" -j ACCEPT -m comment --comment "DDP-AllowSSH"
            apply_rule ip6tables -A INPUT -p tcp --dport "$ssh_port" -j ACCEPT -m comment --comment "DDP-AllowSSH6"
        else
            log_message "${YELLOW}SSH Port ($ssh_port) is invalid. SSH access might be blocked.${NC}"
        fi
    else
        log_message "${YELLOW}SSH protection disabled by configuration. SSH might be allowed without rate limiting if port is open.${NC}"
        # If needed, add a simple ACCEPT rule here if protection is off but access is desired.
        # apply_rule iptables -A INPUT -p tcp --dport "${SETTINGS[SSH_PORT]}" -j ACCEPT ...
    fi

    # HTTP/HTTPS Allowing (ports were checked in protect_slow_http)
    if [[ "${SETTINGS[ENABLE_HTTP_HTTPS_PROTECTION],,}" == "true" ]]; then
        local http_port="${SETTINGS[HTTP_PORT]}"
        local https_port="${SETTINGS[HTTPS_PORT]}"
        if [[ "$http_port" =~ ^[0-9]+$ ]]; then
            apply_rule iptables -A INPUT -p tcp --dport "$http_port" -j ACCEPT -m comment --comment "DDP-AllowHTTP"
            apply_rule ip6tables -A INPUT -p tcp --dport "$http_port" -j ACCEPT -m comment --comment "DDP-AllowHTTP6"
            log_message "${GREEN}Allowing HTTP on port $http_port.${NC}"
        fi
        if [[ "$https_port" =~ ^[0-9]+$ ]]; then
            apply_rule iptables -A INPUT -p tcp --dport "$https_port" -j ACCEPT -m comment --comment "DDP-AllowHTTPS"
            apply_rule ip6tables -A INPUT -p tcp --dport "$https_port" -j ACCEPT -m comment --comment "DDP-AllowHTTPS6"
            log_message "${GREEN}Allowing HTTPS on port $https_port.${NC}"
        fi
    else
         log_message "${YELLOW}HTTP/HTTPS access rules not added as protection module is disabled.${NC}"
         # You might want to add explicit ACCEPT rules here if protection is OFF but you still want web access
         # apply_rule iptables -A INPUT -p tcp --dport "${SETTINGS[HTTP_PORT]}" -j ACCEPT ...
         # apply_rule ip6tables -A INPUT -p tcp --dport "${SETTINGS[HTTPS_PORT]}" -j ACCEPT ...
    fi

    # DNS Allowing (check if UDP protection didn't already allow it)
    local dns_udp_port="${SETTINGS[DNS_UDP_PORT]}"
    local dns_tcp_port="${SETTINGS[DNS_TCP_PORT]}"
    if [[ "$dns_udp_port" =~ ^[0-9]+$ ]]; then
        # Add rule only if UDP protection didn't handle it or is disabled
        if [[ "${SETTINGS[ENABLE_UDP_PROTECTION],,}" != "true" ]] || ! grep -q "DDP-AllowUDP-$dns_udp_port" <<< "$(iptables -S INPUT)"; then
            apply_rule iptables -A INPUT -p udp --dport "$dns_udp_port" -j ACCEPT -m comment --comment "DDP-AllowDNS-UDP"
            apply_rule ip6tables -A INPUT -p udp --dport "$dns_udp_port" -j ACCEPT -m comment --comment "DDP-AllowDNS6-UDP"
            log_message "${GREEN}Allowing DNS (UDP) on port $dns_udp_port.${NC}"
        fi
    fi
    if [[ "$dns_tcp_port" =~ ^[0-9]+$ ]]; then
        apply_rule iptables -A INPUT -p tcp --dport "$dns_tcp_port" -j ACCEPT -m comment --comment "DDP-AllowDNS-TCP"
        apply_rule ip6tables -A INPUT -p tcp --dport "$dns_tcp_port" -j ACCEPT -m comment --comment "DDP-AllowDNS6-TCP"
        log_message "${GREEN}Allowing DNS (TCP) on port $dns_tcp_port.${NC}"
    fi

    # IMPORTANT: Add rules for any other essential services here
    # Example: Allow NTP (UDP 123) if not covered by ALLOWED_UDP_PORTS
    # if ! grep -q "DDP-AllowUDP-123" <<< "$(iptables -S INPUT)"; then
    #    apply_rule iptables -A INPUT -p udp --dport 123 -j ACCEPT -m comment --comment "DDP-AllowNTP-UDP"
    #    apply_rule ip6tables -A INPUT -p udp --dport 123 -j ACCEPT -m comment --comment "DDP-AllowNTP6-UDP"
    # fi

     log_message "${GREEN}Common service access rules applied.${NC}"
}

# --- Persistence and Status ---

save_rules() {
    log_message "${BLUE}Saving firewall rules...${NC}"
    local saved_v4=false
    local saved_v6=false

    if command -v iptables-save &> /dev/null; then
        iptables-save > "$RULES_FILE_V4"
        if [ $? -eq 0 ]; then
            log_message "${GREEN}IPv4 rules saved to $RULES_FILE_V4${NC}"
            saved_v4=true
        else
            log_message "${RED}Failed to save IPv4 rules.${NC}"
        fi
    else
        log_message "${RED}iptables-save command not found. Cannot save IPv4 rules.${NC}"
    fi

    if command -v ip6tables-save &> /dev/null; then
        ip6tables-save > "$RULES_FILE_V6"
         if [ $? -eq 0 ]; then
            log_message "${GREEN}IPv6 rules saved to $RULES_FILE_V6${NC}"
            saved_v6=true
        else
            log_message "${RED}Failed to save IPv6 rules.${NC}"
        fi
    else
        log_message "${RED}ip6tables-save command not found. Cannot save IPv6 rules.${NC}"
    fi

    if $saved_v4 || $saved_v6; then
        echo "ACTIVE" > "$STATUS_FILE"
        create_persistence_script # Create/update script whenever rules are saved
        log_message "${GREEN}Rule persistence configuration updated/created.${NC}"
    else
        log_message "${RED}Rules not saved. Persistence may not work.${NC}"
        echo "INACTIVE" > "$STATUS_FILE" # Mark as inactive if save fails
    fi
}

load_saved_rules() {
     log_message "${BLUE}Loading saved firewall rules...${NC}"
     local loaded_v4=false
     local loaded_v6=false

     if [ -f "$RULES_FILE_V4" ] && command -v iptables-restore &> /dev/null; then
         iptables-restore < "$RULES_FILE_V4"
         if [ $? -eq 0 ]; then
             log_message "${GREEN}Loaded IPv4 rules from $RULES_FILE_V4${NC}"
             loaded_v4=true
         else
             log_message "${RED}Failed to load IPv4 rules from $RULES_FILE_V4${NC}"
         fi
     elif [ ! -f "$RULES_FILE_V4" ]; then
         log_message "${YELLOW}IPv4 rules file ($RULES_FILE_V4) not found.${NC}"
     else
          log_message "${RED}iptables-restore command not found. Cannot load IPv4 rules.${NC}"
     fi

     if [ -f "$RULES_FILE_V6" ] && command -v ip6tables-restore &> /dev/null; then
         ip6tables-restore < "$RULES_FILE_V6"
          if [ $? -eq 0 ]; then
             log_message "${GREEN}Loaded IPv6 rules from $RULES_FILE_V6${NC}"
             loaded_v6=true
         else
             log_message "${RED}Failed to load IPv6 rules from $RULES_FILE_V6${NC}"
         fi
     elif [ ! -f "$RULES_FILE_V6" ]; then
          log_message "${YELLOW}IPv6 rules file ($RULES_FILE_V6) not found.${NC}"
     else
           log_message "${RED}ip6tables-restore command not found. Cannot load IPv6 rules.${NC}"
     fi

     if $loaded_v4 || $loaded_v6; then
         echo "ACTIVE" > "$STATUS_FILE"
         # Re-apply sysctl settings from the persistence script logic
         apply_persistent_sysctl
         log_message "${GREEN}Successfully loaded saved rules. Protection is active.${NC}"
     else
         log_message "${RED}Failed to load any saved rules. Protection might be inactive.${NC}"
         # Consider setting default policies to ACCEPT if loading fails completely? Risky.
         # Better to leave it as is, user should investigate.
         # echo "INACTIVE" > "$STATUS_FILE" # Don't overwrite status if some rules might be partially active
     fi
}

# Function to apply sysctl settings during load (used by persistence script)
apply_persistent_sysctl() {
     log_message "${BLUE}Applying persistent sysctl settings...${NC}"
     local conntrack_optimized=false
     [ -f "$CONFIG_DIR/conntrack_optimized" ] && [[ "$(cat "$CONFIG_DIR/conntrack_optimized")" == "1" ]] && conntrack_optimized=true

     local rp_filter_enabled=false
     [ -f "$CONFIG_FILE" ] && grep -q '^[[:space:]]*ENABLE_RP_FILTER[[:space:]]*=[[:space:]]*true' "$CONFIG_FILE" && rp_filter_enabled=true

     local syn_protection_enabled=false
     [ -f "$CONFIG_FILE" ] && grep -q '^[[:space:]]*ENABLE_SYN_PROTECTION[[:space:]]*=[[:space:]]*true' "$CONFIG_FILE" && syn_protection_enabled=true


     if $rp_filter_enabled; then
         sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null 2>&1
         sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1
     fi

     if $syn_protection_enabled; then
         sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1
         sysctl -w net.ipv4.tcp_max_syn_backlog=2048 >/dev/null 2>&1
         sysctl -w net.ipv4.tcp_synack_retries=1 >/dev/null 2>&1
     fi

     if $conntrack_optimized; then
         modprobe nf_conntrack >/dev/null 2>&1 # Ensure module is loaded
         if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
             sysctl -w net.netfilter.nf_conntrack_max=1000000 >/dev/null 2>&1
             sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=1800 >/dev/null 2>&1
             sysctl -w net.netfilter.nf_conntrack_tcp_timeout_syn_recv=30 >/dev/null 2>&1
             sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=60 >/dev/null 2>&1
             sysctl -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=60 >/dev/null 2>&1
             sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=60 >/dev/null 2>&1
         fi
     fi
      log_message "${GREEN}Persistent sysctl settings applied.${NC}"
}

# Create script and configure system to load rules on boot
create_persistence_script() {
    log_message "${BLUE}Creating/Updating persistence script: $PERSISTENCE_SCRIPT${NC}"
    # Create the script that loads rules and applies sysctl settings
    cat > "$PERSISTENCE_SCRIPT" << EOF
#!/bin/bash
# Load saved firewall rules and apply sysctl settings on boot

LOG_FILE="/var/log/ddos-protection-boot.log"
CONFIG_DIR="/etc/ddos-protection"
RULES_FILE_V4="$CONFIG_DIR/iptables.rules"
RULES_FILE_V6="$CONFIG_DIR/ip6tables.rules"
STATUS_FILE="$CONFIG_DIR/protection_status"

echo "\$(date): Starting DDoS Protection Persistence Script" >> "\$LOG_FILE"

# Apply sysctl settings first
echo "\$(date): Applying persistent sysctl settings..." >> "\$LOG_FILE"
conntrack_optimized=false
[ -f "$CONFIG_DIR/conntrack_optimized" ] && [[ "\$(cat "$CONFIG_DIR/conntrack_optimized")" == "1" ]] && conntrack_optimized=true

rp_filter_enabled=false
[ -f "$CONFIG_DIR/ddos.conf" ] && grep -q '^[[:space:]]*ENABLE_RP_FILTER[[:space:]]*=[[:space:]]*true' "$CONFIG_DIR/ddos.conf" && rp_filter_enabled=true

syn_protection_enabled=false
[ -f "$CONFIG_DIR/ddos.conf" ] && grep -q '^[[:space:]]*ENABLE_SYN_PROTECTION[[:space:]]*=[[:space:]]*true' "$CONFIG_DIR/ddos.conf" && syn_protection_enabled=true

if \$rp_filter_enabled; then
    sysctl -w net.ipv4.conf.default.rp_filter=1 >> "\$LOG_FILE" 2>&1
    sysctl -w net.ipv4.conf.all.rp_filter=1 >> "\$LOG_FILE" 2>&1
fi

if \$syn_protection_enabled; then
    sysctl -w net.ipv4.tcp_syncookies=1 >> "\$LOG_FILE" 2>&1
    sysctl -w net.ipv4.tcp_max_syn_backlog=2048 >> "\$LOG_FILE" 2>&1
    sysctl -w net.ipv4.tcp_synack_retries=1 >> "\$LOG_FILE" 2>&1
fi

if \$conntrack_optimized; then
    modprobe nf_conntrack >> "\$LOG_FILE" 2>&1
    if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
        sysctl -w net.netfilter.nf_conntrack_max=1000000 >> "\$LOG_FILE" 2>&1
        sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=1800 >> "\$LOG_FILE" 2>&1
        sysctl -w net.netfilter.nf_conntrack_tcp_timeout_syn_recv=30 >> "\$LOG_FILE" 2>&1
        sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=60 >> "\$LOG_FILE" 2>&1
        sysctl -w net.netfilter.nf_conntrack_tcp_timeout_fin_wait=60 >> "\$LOG_FILE" 2>&1
        sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close_wait=60 >> "\$LOG_FILE" 2>&1
    else
        echo "\$(date): nf_conntrack sysctl parameters not found during boot." >> "\$LOG_FILE"
    fi
fi
echo "\$(date): sysctl settings applied." >> "\$LOG_FILE"

# Load firewall rules
echo "\$(date): Loading firewall rules..." >> "\$LOG_FILE"
loaded_something=false
if [ -f "\$RULES_FILE_V4" ] && command -v iptables-restore &> /dev/null; then
    iptables-restore < "\$RULES_FILE_V4" >> "\$LOG_FILE" 2>&1 && loaded_something=true
    echo "\$(date): Attempted load IPv4 rules." >> "\$LOG_FILE"
fi
if [ -f "\$RULES_FILE_V6" ] && command -v ip6tables-restore &> /dev/null; then
    ip6tables-restore < "\$RULES_FILE_V6" >> "\$LOG_FILE" 2>&1 && loaded_something=true
    echo "\$(date): Attempted load IPv6 rules." >> "\$LOG_FILE"
fi

if \$loaded_something; then
    echo "ACTIVE" > "\$STATUS_FILE"
    echo "\$(date): Rules loaded, status set to ACTIVE." >> "\$LOG_FILE"
else
    echo "INACTIVE" > "\$STATUS_FILE"
    echo "\$(date): Failed to load rules or files not found, status set to INACTIVE." >> "\$LOG_FILE"
    # Fallback to default open policy if rules fail to load? Or keep DROP? Keep DROP is safer.
    # Consider adding basic ACCEPT rules here if total failure is detected and desired.
fi

echo "\$(date): DDoS Protection Persistence Script finished." >> "\$LOG_FILE"
exit 0
EOF

    chmod +x "$PERSISTENCE_SCRIPT"
    log_message "${GREEN}Created persistence script: $PERSISTENCE_SCRIPT${NC}"

    # --- Configure Persistence Method ---
    local persistence_configured=false

    # 1. Systemd (Preferred modern method)
    if command -v systemctl &> /dev/null && [ -d "/etc/systemd/system" ]; then
        log_message "${BLUE}Configuring systemd service...${NC}"
        cat > "/etc/systemd/system/ddos-protection.service" << EOF
[Unit]
Description=DDoS Protection Firewall Rules Loader
After=network-online.target network.target
Wants=network-online.target
DefaultDependencies=no
Before=sysinit.target shutdown.target
ConditionFileNotEmpty=$PERSISTENCE_SCRIPT

[Service]
Type=oneshot
ExecStart=$PERSISTENCE_SCRIPT
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable ddos-protection.service
        log_message "${GREEN}Systemd service 'ddos-protection.service' created and enabled.${NC}"
        persistence_configured=true
    fi

    # 2. iptables-persistent / netfilter-persistent (Debian/Ubuntu specific)
    if command -v netfilter-persistent &> /dev/null; then
         log_message "${BLUE}Using netfilter-persistent (Debian/Ubuntu)...${NC}"
         # It should automatically pick up the saved rules if installed and enabled.
         # Ensure the service is enabled.
         systemctl enable netfilter-persistent.service 2>/dev/null
         log_message "${GREEN}Ensure 'netfilter-persistent' service is enabled and run 'netfilter-persistent save' if needed.${NC}"
         # Note: Our custom script might conflict if both run. Systemd method is cleaner if available.
         # Consider disabling netfilter-persistent if using our systemd service.
         # systemctl disable netfilter-persistent.service
         persistence_configured=true # Mark as configured, even if potentially redundant
    elif command -v service &> /dev/null && [ -f /etc/init.d/iptables-persistent ]; then
         log_message "${BLUE}Using iptables-persistent (older Debian/Ubuntu)...${NC}"
         service iptables-persistent save 2>/dev/null
         update-rc.d iptables-persistent enable 2>/dev/null
         log_message "${GREEN}Ensure 'iptables-persistent' service is enabled.${NC}"
         persistence_configured=true
    fi

    # 3. iptables-services (RHEL/CentOS specific)
    if command -v systemctl &> /dev/null && systemctl list-unit-files | grep -q iptables.service; then
         log_message "${BLUE}Using iptables-services (RHEL/CentOS)...${NC}"
         # Rules should be saved to /etc/sysconfig/iptables and /etc/sysconfig/ip6tables by iptables-save
         # Our save_rules function saves to our config dir, need to link or copy?
         # Let's rely on our systemd service which is more universal.
         # Or copy the rules:
         # cp "$RULES_FILE_V4" /etc/sysconfig/iptables
         # cp "$RULES_FILE_V6" /etc/sysconfig/ip6tables
         # systemctl enable iptables.service
         # systemctl enable ip6tables.service
         log_message "${YELLOW}Consider enabling 'iptables' and 'ip6tables' services if not using the ddos-protection systemd service.${NC}"
         # persistence_configured=true # Don't mark as configured unless we actively set it up.
    fi

    # 4. rc.local (Legacy fallback)
    if [ -f "/etc/rc.local" ] && ! $persistence_configured; then
        log_message "${YELLOW}Using legacy /etc/rc.local for persistence...${NC}"
        # Remove previous entries to avoid duplicates
        sed -i "\|$PERSISTENCE_SCRIPT|d" /etc/rc.local
        # Add entry before 'exit 0' if it exists
        if grep -q '^exit 0' /etc/rc.local; then
            sed -i "/^exit 0/i $PERSISTENCE_SCRIPT" /etc/rc.local
        else
            # Append if 'exit 0' is missing
            echo "$PERSISTENCE_SCRIPT" >> /etc/rc.local
        fi
        chmod +x /etc/rc.local
        log_message "${GREEN}Added persistence script to /etc/rc.local.${NC}"
        persistence_configured=true
    fi

    # 5. WSL Specific (Attempt to run on Windows startup)
    if grep -qiE 'Microsoft|WSL' /proc/version; then
        log_message "${BLUE}Attempting WSL persistence via Windows Task Scheduler...${NC}"
        local wsl_distro_name
        wsl_distro_name=$(lsb_release -si 2>/dev/null || grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"' || echo "DefaultWSLDistro")
        local task_name="WSLLoadDDoSProtection_${wsl_distro_name}"
        local wsl_script_path
        wsl_script_path=$(wslpath -w "$PERSISTENCE_SCRIPT") # Convert Linux path to Windows path

        # Use PowerShell from within WSL to create/update the scheduled task
        # This runs the persistence script as root within the specific WSL distro on Windows login
        powershell.exe -Command "Unregister-ScheduledTask -TaskName '$task_name' -Confirm:\$false > \$null 2>&1; \$Action = New-ScheduledTaskAction -Execute 'wsl.exe' -Argument '-d $wsl_distro_name -u root $PERSISTENCE_SCRIPT'; \$Trigger = New-ScheduledTaskTrigger -AtLogOn; \$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0; Register-ScheduledTask -TaskName '$task_name' -Action \$Action -Trigger \$Trigger -Settings \$Settings -User (whoami.exe) -RunLevel Highest -Force"

        if [ $? -eq 0 ]; then
            log_message "${GREEN}Created/Updated Windows Scheduled Task '$task_name' to run script on login.${NC}"
            log_message "${YELLOW}Note: This requires your Windows user to have sufficient privileges.${NC}"
            persistence_configured=true
        else
            log_message "${RED}Failed to create Windows Scheduled Task for WSL persistence.${NC}"
            log_message "${YELLOW}Manual configuration may be needed. Run '$PERSISTENCE_SCRIPT' manually after WSL starts.${NC}"
        fi
    fi


    if ! $persistence_configured; then
         log_message "${RED}Could not configure automatic persistence. Rules must be loaded manually after reboot using option 8 or by running: $PERSISTENCE_SCRIPT${NC}"
    fi
}

show_status() {
    echo -e "${BLUE}================ DDoS Protection Status ================${NC}"
    load_config # Ensure current config is reflected

    # Check Status File
    local status="UNKNOWN"
    if [ -f "$STATUS_FILE" ]; then
        status=$(cat "$STATUS_FILE")
    fi
    echo -e "${BLUE}Overall Status:${NC} $status"

    # Check for Marker Rule
    local marker_found_v4=false
    local marker_found_v6=false
    command -v iptables &>/dev/null && iptables -S INPUT | grep -q 'DDP-ACTIVE-MARKER' && marker_found_v4=true
    command -v ip6tables &>/dev/null && ip6tables -S INPUT | grep -q 'DDP-ACTIVE-MARKER' && marker_found_v6=true

    if $marker_found_v4 || $marker_found_v6; then
        echo -e "${GREEN}IPTables Active Marker Found (IPv4: $marker_found_v4, IPv6: $marker_found_v6)${NC}"
        if [[ "$status" != "ACTIVE" ]]; then
             echo -e "${YELLOW}Warning: Status file ($STATUS_FILE) shows '$status' but marker rule exists.${NC}"
        fi
    else
        echo -e "${RED}IPTables Active Marker NOT Found. Protection likely inactive or incomplete.${NC}"
         if [[ "$status" == "ACTIVE" ]]; then
             echo -e "${YELLOW}Warning: Status file ($STATUS_FILE) shows 'ACTIVE' but marker rule is missing.${NC}"
        fi
    fi

    echo -e "\n${BLUE}Configuration & Lists:${NC}"
    echo -e "  Config File: $CONFIG_FILE"
    echo -e "  Whitelist:   $WHITELIST_FILE ($(grep -vcE '^\s*(#|$)' "$WHITELIST_FILE" 2>/dev/null || echo 0) entries)"
    echo -e "  Blacklist:   $BLACKLIST_FILE ($(grep -vcE '^\s*(#|$)' "$BLACKLIST_FILE" 2>/dev/null || echo 0) entries)"
    echo -e "  Log File:    $LOG_FILE"

    echo -e "\n${BLUE}Enabled Protection Modules (from config):${NC}"
    for key in "${!SETTINGS[@]}"; do
        if [[ "$key" == ENABLE_* ]]; then
            local module_name="${key#ENABLE_}"
            module_name="${module_name//_/ }" # Replace underscores with spaces
            local enabled="${SETTINGS[$key]}"
            local color="${RED}"
            [[ "${enabled,,}" == "true" ]] && color="${GREEN}"
            printf "  %-30s: %b%s%b\n" "$module_name" "$color" "$enabled" "$NC"
        fi
    done

    echo -e "\n${BLUE}Key Limits (from config):${NC}"
    printf "  %-30s: %s\n" "SYN Limit/Burst" "${SETTINGS[SYN_LIMIT]} / ${SETTINGS[SYN_BURST]}"
    printf "  %-30s: %s\n" "ICMP Limit" "${SETTINGS[ICMP_LIMIT]}"
    printf "  %-30s: %s\n" "Overall Connection Limit" "${SETTINGS[CONN_LIMIT]}"
    printf "  %-30s: %s\n" "HTTP Connection Limit" "${SETTINGS[HTTP_CONN_LIMIT]}"
    printf "  %-30s: %s\n" "HTTPS Connection Limit" "${SETTINGS[HTTPS_CONN_LIMIT]}"
    printf "  %-30s: %s\n" "SSH Connection Limit/Time" "${SETTINGS[SSH_CONN_LIMIT]} / ${SETTINGS[SSH_CONN_SECONDS]}s"
    printf "  %-30s: %s\n" "UDP Rate Limit/Burst" "${SETTINGS[UDP_LIMIT]} / ${SETTINGS[UDP_BURST]}"
    printf "  %-30s: %s\n" "Allowed UDP Ports" "${SETTINGS[ALLOWED_UDP_PORTS]}"


    echo -e "\n${BLUE}Persistence:${NC}"
    if [ -f "$RULES_FILE_V4" ] || [ -f "$RULES_FILE_V6" ]; then
        echo -e "  Saved Rule Files Found: ${GREEN}Yes${NC} (IPv4: $([[ -f "$RULES_FILE_V4" ]] && echo 'Yes' || echo 'No'), IPv6: $([[ -f "$RULES_FILE_V6" ]] && echo 'Yes' || echo 'No'))"
        # Check if persistence mechanism seems configured
        if systemctl is-enabled ddos-protection.service >/dev/null 2>&1 || \
           (command -v netfilter-persistent &>/dev/null && systemctl is-enabled netfilter-persistent.service >/dev/null 2>&1) || \
           (command -v service &>/dev/null && service iptables-persistent status >/dev/null 2>&1) || \
           ([ -f /etc/rc.local ] && grep -q "$PERSISTENCE_SCRIPT" /etc/rc.local) || \
           (grep -qiE 'Microsoft|WSL' /proc/version && powershell.exe -Command "Get-ScheduledTask -TaskName 'WSLLoadDDoSProtection_*' > \$null 2>&1; exit \$LASTEXITCODE" > /dev/null 2>&1); then
             echo -e "  Persistence Mechanism: ${GREEN}Likely Enabled${NC}"
        else
             echo -e "  Persistence Mechanism: ${RED}Likely Disabled or Not Found${NC}"
        fi
    else
        echo -e "  Saved Rule Files Found: ${RED}No${NC}"
        echo -e "  Persistence Mechanism: ${RED}Disabled (no rules to load)${NC}"
    fi

    # WSL Specific Warning
    if grep -qiE 'Microsoft|WSL' /proc/version; then
         echo -e "\n${YELLOW}--- WSL Note ---"
         echo -e "You are running in WSL. ${RED}IMPORTANT:${NC}"
         echo -e "iptables rules within WSL primarily protect services running *inside* the WSL instance."
         echo -e "Traffic directed to ports on the Windows host (even if forwarded to WSL) hits the Windows network stack *first*."
         echo -e "For effective protection of services exposed via Windows port forwarding, configure the ${BLUE}Windows Firewall${NC} on the host system."
         echo -e "This script's rules will apply mainly to direct WSL-to-WSL or WSL outbound traffic, and traffic *after* it has been forwarded by Windows.${NC}"
         echo -e "${YELLOW}---------------${NC}"
    fi
     echo -e "\n${BLUE}====================================================${NC}"
}

view_current_rules() {
    log_message "${BLUE}Displaying current firewall rules...${NC}"
    if command -v iptables &>/dev/null; then
        echo -e "\n--- IPv4 Rules (iptables) ---"
        iptables -L -v -n --line-numbers
        echo -e "\n--- IPv4 NAT Table ---"
        iptables -t nat -L -v -n --line-numbers
        echo -e "\n--- IPv4 Mangle Table ---"
        iptables -t mangle -L -v -n --line-numbers
    else
        echo -e "${YELLOW}iptables command not found.${NC}"
    fi

    if command -v ip6tables &>/dev/null; then
        echo -e "\n--- IPv6 Rules (ip6tables) ---"
        ip6tables -L -v -n --line-numbers
         echo -e "\n--- IPv6 Mangle Table ---"
        ip6tables -t mangle -L -v -n --line-numbers
    else
        echo -e "${YELLOW}ip6tables command not found.${NC}"
    fi
    echo -e "\n${BLUE}Rule display finished.${NC}"
}


disable_protection() {
    log_message "${RED}Disabling DDoS protection and allowing all traffic...${NC}"

    # Flush all rules and chains
    reset_firewall

    # Set default policies to ACCEPT (allow everything)
    apply_rule iptables -P INPUT ACCEPT
    apply_rule iptables -P FORWARD ACCEPT # Adjust if you need forwarding restrictions
    apply_rule iptables -P OUTPUT ACCEPT
    apply_rule ip6tables -P INPUT ACCEPT
    apply_rule ip6tables -P FORWARD ACCEPT # Adjust if you need forwarding restrictions
    apply_rule ip6tables -P OUTPUT ACCEPT

    # Mark protection as inactive
    echo "INACTIVE" > "$STATUS_FILE"

    # Optionally remove saved rules and disable persistence
    echo -e "${YELLOW}Do you want to remove saved rule files and disable persistence? (y/n)${NC}"
    read -r remove_persistence
    if [[ "$remove_persistence" =~ ^[Yy]$ ]]; then
        rm -f "$RULES_FILE_V4" "$RULES_FILE_V6" "$PERSISTENCE_SCRIPT"
        log_message "${RED}Removed saved rule files and persistence script.${NC}"
        # Attempt to disable persistence mechanisms
        if command -v systemctl &> /dev/null; then
            systemctl disable ddos-protection.service 2>/dev/null && log_message "${RED}Disabled systemd service.${NC}"
            systemctl disable netfilter-persistent.service 2>/dev/null # In case it was used
            systemctl disable iptables.service 2>/dev/null # RHEL/CentOS
            systemctl disable ip6tables.service 2>/dev/null # RHEL/CentOS
        fi
        if [ -f "/etc/rc.local" ]; then
             sed -i "\|$PERSISTENCE_SCRIPT|d" /etc/rc.local && log_message "${RED}Removed entry from rc.local.${NC}"
        fi
        if grep -qiE 'Microsoft|WSL' /proc/version; then
             powershell.exe -Command "Unregister-ScheduledTask -TaskName 'WSLLoadDDoSProtection_*' -Confirm:\$false > \$null 2>&1" && log_message "${RED}Removed WSL Scheduled Task persistence.${NC}"
        fi
        rm -f "$CONFIG_DIR/conntrack_optimized"
    fi

    log_message "${RED}Protection disabled. Firewall policies set to ACCEPT.${NC}"
}

apply_all_protections() {
     log_message "${GREEN}=== Applying All DDoS Protections ==="
     load_config
     configure_sysctl      # Apply kernel parameter tweaks first
     reset_firewall        # Flush existing rules, set default DROP
     setup_base_rules      # Apply loopback, established, block/whitelist, invalid drop, marker
     # Apply specific protection modules based on config
     protect_syn_flood
     protect_icmp
     protect_port_scan
     protect_rst_flood
     protect_slow_http
     protect_udp_flood     # This sets up UDP filtering chain and general limits
     allow_common_services # Allow specific necessary services (SSH, HTTP/S, DNS etc.)
     apply_drop_logging    # Add logging rules if enabled (near the end)

     # The default INPUT/FORWARD policy remains DROP, catching anything not explicitly allowed/accepted.

     # Mark as active *only if* the marker rule was successfully added
    local marker_found_v4=false
    local marker_found_v6=false
    command -v iptables &>/dev/null && iptables -S INPUT | grep -q 'DDP-ACTIVE-MARKER' && marker_found_v4=true
    command -v ip6tables &>/dev/null && ip6tables -S INPUT | grep -q 'DDP-ACTIVE-MARKER' && marker_found_v6=true
    if $marker_found_v4 || $marker_found_v6; then
        echo "ACTIVE" > "$STATUS_FILE"
        log_message "${GREEN}All protection rules applied successfully! Status: ACTIVE${NC}"
        save_rules # Save the newly applied rules and update persistence
    else
        echo "INACTIVE" > "$STATUS_FILE"
        log_message "${RED}Failed to apply all protection rules (marker rule missing). Status: INACTIVE${NC}"
        log_message "${RED}Review logs for errors. Firewall may be in an incomplete state.${NC}"
    fi
}


# --- Main Menu ---
main_menu() {
    clear
    echo -e "${BLUE}====================================================${NC}"
    echo -e "${BLUE}===                 LightProt v1                 ===${NC}"
    echo -e "${BLUE}===                 by QKing                     ===${NC}"
    echo -e "${BLUE}====================================================${NC}"
    echo -e " Status: $(cat "$STATUS_FILE" 2>/dev/null || echo "UNKNOWN")  | Config: $CONFIG_FILE"
    echo -e "----------------------------------------------------"
    echo -e "${GREEN} 1.${NC} Apply All Protections & Save Rules"
    echo -e "${YELLOW} 2.${NC} Show Status Details"
    echo -e "${YELLOW} 3.${NC} View Current Firewall Rules (iptables -L)"
    echo -e "--------------------- Configuration --------------------"
    echo -e "${BLUE} 4.${NC} Add IPs to Whitelist"
    echo -e "${BLUE} 5.${NC} Remove IPs from Whitelist"
    echo -e "${BLUE} 6.${NC} Add IPs to Blocklist"
    echo -e "${BLUE} 7.${NC} Remove IPs from Blocklist"
    echo -e "${BLUE} 8.${NC} Reload Settings from Config File (${GREEN}Does not apply rules${NC})"
    echo -e "---------------------- Maintenance ---------------------"
    echo -e "${CYAN} 9.${NC} Load Saved Rules (${RED}Overwrites current rules${NC})"
    echo -e "${CYAN}10.${NC} Manually Save Current Rules"
    echo -e "${RED}11.${NC} Disable Protection (${BOLD}Allows ALL traffic${NC})"
    echo -e "----------------------------------------------------"
    echo -e "${PURPLE}12.${NC} Exit"
    echo -e "\n${YELLOW}Enter your choice:${NC}"
    read -r choice

    case $choice in
        1) apply_all_protections ;;
        2) show_status ;;
        3) view_current_rules ;;
        4) manage_ip_list "$WHITELIST_FILE" "Whitelist" "add" ;;
        5) manage_ip_list "$WHITELIST_FILE" "Whitelist" "remove" ;;
        6) manage_ip_list "$BLACKLIST_FILE" "Blacklist" "add" ;;
        7) manage_ip_list "$BLACKLIST_FILE" "Blacklist" "remove" ;;
        8) load_config ;;
        9) load_saved_rules ;;
       10) save_rules ;;
       11) disable_protection ;;
       12) echo -e "${GREEN}Exiting. Current firewall state remains active.${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid choice.${NC}" ;;
    esac

    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r dummy_input
    main_menu
}

# --- Script Entry Point ---

# Setup Colors (if possible)
if tput setaf 1 >/dev/null 2>&1; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    PURPLE=$(tput setaf 5)
    CYAN=$(tput setaf 6)
    BOLD=$(tput bold)
    NC=$(tput sgr0) # No Color
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
fi

# Initial checks
check_root
check_command "iptables"
check_command "ip6tables"
check_command "sysctl"
check_command "modprobe"
# check_command "iptables-save" # Checked within functions where needed
# check_command "iptables-restore" # Checked within functions where needed

# Initialize configuration files and directories
initialize_config

# Load initial configuration
load_config

# Check WSL and show initial warning if detected
if grep -qiE 'Microsoft|WSL' /proc/version; then
    log_message "${YELLOW}--- WSL Detection ---${NC}"
    log_message "${YELLOW}Running in WSL. Remember the networking limitations described in the status (Option 2).${NC}"
    log_message "${YELLOW}Windows Firewall on the host is recommended for ports forwarded from Windows.${NC}"
    sleep 2
fi

# Start the main interactive menu
main_menu

exit 0
