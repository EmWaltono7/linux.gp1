<<<<<<< HEAD
#!/bin/bash
# manage_users.sh
# Interactively review and manage local and admin users.
# Tested on Linux Mint / Ubuntu.

set -euo pipefail

echo "[+] Starting interactive user management..."
echo

# Quick environment checks (helpful for Mint 21)
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This script is intended for Linux systems (tested on Mint/Ubuntu). Exiting."
    exit 1
fi

# Ensure dpkg/apt are available
if ! command -v dpkg >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1; then
    echo "Required package tools (dpkg/apt-get) not found. Ensure you're running on Debian/Ubuntu-based Linux." 
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Note: this script uses sudo for privileged operations. You may be prompted for your password."
fi

# --- Step 1: Process all local users ---
# We'll exclude system accounts (UID < 1000) and 'nobody'.
echo "=== Local User Review ==="
echo

mapfile -t local_users < <(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)

for user in "${local_users[@]}"; do
    echo "User found: $user"
    read -rp "Keep this user? (y/n): " keep
    if [[ "$keep" =~ ^[Nn]$ ]]; then
        echo "Deleting user: $user"
        sudo deluser --remove-home "$user"
    else
        echo "Keeping user: $user"
    fi
    echo
done

    # Quick environment checks (helpful for Mint 21)
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "This script is intended for Linux systems (tested on Mint/Ubuntu). Exiting."
        exit 1
    fi

    # Ensure dpkg/apt are available
    if ! command -v dpkg >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1; then
        echo "Required package tools (dpkg/apt-get) not found. Ensure you're running on Debian/Ubuntu-based Linux." 
        exit 1
    fi

    # --- Step 2: Process administrators ---
    echo "=== Administrator Review ==="
    echo

    # Get comma-separated members of 'sudo' group
    sudo_members=$(getent group sudo | awk -F: '{print $4}')

    if [[ -z "$sudo_members" ]]; then
        echo "No members found in 'sudo' group."
    else
        # Split on commas into an array and iterate one admin at a time
        IFS=',' read -ra admins <<< "$sudo_members"
        for admin in "${admins[@]}"; do
            # trim whitespace (usernames won't contain spaces)
            admin="${admin#"${admin%%[![:space:]]*}"}"
            admin="${admin%"${admin##*[![:space:]]}"}"
            [[ -z "$admin" ]] && continue

            echo "Admin user: $admin"
            read -rp "Keep this user as admin? (y/n): " keep_admin
            if [[ "$keep_admin" =~ ^[Nn]$ ]]; then
                echo "Removing $admin from admin group..."
                sudo deluser "$admin" sudo
            else
                echo "Keeping $admin as admin."
            fi
            echo
        done
    fi

    # Exclude pseudo-filesystems for speed and to avoid odd results

    # --- Hidden User Audit ---
    echo "=== Hidden User Audit ==="
    echo
    # Find users that may be 'hidden' or stale: either no home directory, home doesn't exist, or shell is non-interactive
    mapfile -t hidden_users < <(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1":"$6":"$7}' /etc/passwd | \
        awk -F: '{
            user=$1; home=$2; shell=$3;
            cmd = "test -d \"" home "\""
            home_missing = (home=="" || system(cmd) != 0)
            if (home_missing || shell=="/usr/sbin/nologin" || shell=="/sbin/nologin" || shell=="/bin/false" || shell=="/usr/bin/false")
                print user":"home":"shell
        }')

    if ((${#hidden_users[@]} == 0)); then
        echo "✅ No obvious hidden/stale users detected."
    else
        echo "⚠️ Possible hidden/stale users found:" 
        for entry in "${hidden_users[@]}"; do
            IFS=':' read -r user home shell <<< "$entry"
            echo " - $user (home: $home, shell: $shell)"
        done
        echo
        # Prompt for each user individually
        for entry in "${hidden_users[@]}"; do
            IFS=':' read -r user home shell <<< "$entry"
            echo
            read -rp "Remove user $user (home: $home, shell: $shell)? (y/N): " remove_user
            if [[ "$remove_user" =~ ^[Yy]$ ]]; then
                echo "[+] Backing up and removing user: $user"
                # Backup home if exists
                home_dir=$(getent passwd "$user" | cut -d: -f6)
                if [[ -n "$home_dir" && -d "$home_dir" ]]; then
                    backup_path="/tmp/${user}_home_backup_$(date +%F-%H%M%S)"
                    echo "[+] Backing up $home_dir to $backup_path"
                    sudo cp -a "$home_dir" "$backup_path" || true
                fi
                if sudo deluser --remove-home "$user"; then
                    echo "Removed $user"
                else
                    echo "⚠️ Failed to remove $user"
                fi
            else
                echo "Skipping $user"
            fi
        done
    fi



# --- Step 3: Apply Secure Account Policies ---
echo "=== Applying Secure Account Policies ==="
echo

# 1) Secure password hashing algorithm (use SHA-512)
echo "[+] Setting SHA-512 password hashing..."
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t12/' /etc/login.defs || echo "PASS_MIN_LEN 12" | sudo tee -a /etc/login.defs >/dev/null

if grep -q "pam_unix.so" /etc/pam.d/common-password; then
    sudo sed -i 's/pam_unix.so.*/pam_unix.so sha512/' /etc/pam.d/common-password
fi

# 2) Secure password quality rules
echo "[+] Configuring /etc/security/pwquality.conf..."
sudo cp /etc/security/pwquality.conf /etc/security/pwquality.conf.bak.$(date +%F-%H%M%S)
sudo sed -i '/^minlen/d' /etc/security/pwquality.conf
sudo sed -i '/^minclass/d' /etc/security/pwquality.conf
sudo sed -i '/^maxrepeat/d' /etc/security/pwquality.conf
sudo sed -i '/^maxsequence/d' /etc/security/pwquality.conf
sudo sed -i '/^dictcheck/d' /etc/security/pwquality.conf

cat <<'EOF' | sudo tee -a /etc/security/pwquality.conf >/dev/null
minlen = 12
minclass = 3
maxrepeat = 2
maxsequence = 2
dictcheck = 1
EOF

# 3) Disallow blank passwords
echo "[+] Disallowing blank passwords..."
# Remove any 'nullok' options from PAM configuration files (prevents blank passwords)
if sudo grep -RIn "\bnullok\b" /etc/pam.d >/dev/null 2>&1; then
    echo "[+] Removing 'nullok' option from PAM configuration files under /etc/pam.d/..."
    # Use word-boundary replacement to avoid accidental partial matches
    sudo sed -i 's/\bnullok\b//g' /etc/pam.d/* 2>/dev/null || true
    echo "[+] 'nullok' removed where present."
else
    echo "nullok option not present in /etc/pam.d — already safe."
fi

# Ensure SSH does not allow empty passwords
sshd_cfg_file="/etc/ssh/sshd_config"
if [[ -w "$sshd_cfg_file" ]] || sudo test -w "$sshd_cfg_file"; then
    sudo sed -i '/^PermitEmptyPasswords/d' "$sshd_cfg_file" 2>/dev/null || true
    echo "PermitEmptyPasswords no" | sudo tee -a "$sshd_cfg_file" >/dev/null
    echo "[+] Enforced 'PermitEmptyPasswords no' in $sshd_cfg_file"
else
    echo "⚠️ Could not write to $sshd_cfg_file to enforce PermitEmptyPasswords. Run with appropriate privileges to enforce SSH empty-password policy."
fi

# 4) Confirming settings
echo
echo "=== Final Policy Summary ==="
echo "Password hashing: SHA-512"
echo "Max password age: 90 days"
echo "Min password age: 1 day"
echo "Min password length: 12"
echo "Min character classes: 3"
echo "Blank passwords: Disabled"
echo
echo "✅ Secure password and account policies applied successfully."
echo "=== Done! ==="

# --- Step 4: Apply Local Security Policies ---
echo "=== Applying Local Security Policies ==="
echo

# 1) Sudo requires authentication (no NOPASSWD)
echo "[+] Ensuring sudo requires authentication..."
sudo sed -i '/NOPASSWD/d' /etc/sudoers
sudo find /etc/sudoers.d -type f -exec sudo sed -i '/NOPASSWD/d' {} \;

# 2) Disable 'authenticate' bypass in sudoers
echo "[+] Ensuring sudo commands require authentication..."
sudo sed -i '/!authenticate/d' /etc/sudoers
sudo find /etc/sudoers.d -type f -exec sudo sed -i '/!authenticate/d' {} \;

# 3) Disable SysRq (magic SysRq key)
echo "[+] Disabling SysRq key..."
sudo sysctl -w kernel.sysrq=0 >/dev/null
sudo sed -i '/^kernel.sysrq/d' /etc/sysctl.conf
echo "kernel.sysrq = 0" | sudo tee -a /etc/sysctl.conf >/dev/null

# 4) Enable Address Space Layout Randomization (ASLR)
echo "[+] Enabling Address Space Layout Randomization (ASLR)..."
sudo sysctl -w kernel.randomize_va_space=2 >/dev/null
sudo sed -i '/^kernel.randomize_va_space/d' /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf >/dev/null

# 5) Log packets with impossible (martian) addresses
echo "[+] Enabling logging of packets with impossible (martian) addresses..."
sudo sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null
sudo sysctl -w net.ipv4.conf.default.log_martians=1 >/dev/null

# Also enable log_martians on all current interfaces to ensure immediate kernel logging
for conf in /proc/sys/net/ipv4/conf/*/log_martians; do
    if [[ -w "$conf" ]]; then
        echo 1 | sudo tee "$conf" >/dev/null || true
    fi
done

# Ensure sysctl.conf has the persistent settings for all and default
sudo sed -i '/net.ipv4.conf.all.log_martians/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.conf.default.log_martians/d' /etc/sysctl.conf
cat <<'EOF' | sudo tee -a /etc/sysctl.conf >/dev/null
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF

# Ensure kernel printk verbosity allows kernel messages to reach kernel log
sudo sed -i '/^kernel.printk/d' /etc/sysctl.conf
sudo sysctl -w kernel.printk="4 4 1 7" >/dev/null || true
echo "kernel.printk = 4 4 1 7" | sudo tee -a /etc/sysctl.conf >/dev/null

# 6) Restrict hardlink and symlink creation
echo "[+] Restricting hardlink and symlink creation to owner only..."
sudo sysctl -w fs.protected_hardlinks=1 >/dev/null
sudo sysctl -w fs.protected_symlinks=1 >/dev/null
sudo sed -i '/protected_hardlinks/d' /etc/sysctl.conf
sudo sed -i '/protected_symlinks/d' /etc/sysctl.conf
cat <<'EOF' | sudo tee -a /etc/sysctl.conf >/dev/null
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

# 7) Apply sysctl settings immediately
sudo sysctl -p >/dev/null
echo
echo "✅ Local security policies applied successfully."
echo

# 8) Ensure secure permissions on sensitive files
echo "[+] Ensuring secure permissions for sensitive config files..."
if [[ -e /etc/shadow ]]; then
    echo "[+] Setting owner root:shadow and mode 640 on /etc/shadow"
    sudo chown root:shadow /etc/shadow || true
    sudo chmod 640 /etc/shadow || true
    echo "    -> $(stat -c '%U:%G %a %n' /etc/shadow)"
else
    echo "⚠️ /etc/shadow not found; skipping permission fix."
fi

sshd_cfg="/etc/ssh/sshd_config"
if [[ -e "$sshd_cfg" ]]; then
    echo "[+] Setting owner root:root and mode 600 on $sshd_cfg"
    sudo chown root:root "$sshd_cfg" || true
    sudo chmod 600 "$sshd_cfg" || true
    echo "    -> $(stat -c '%U:%G %a %n' "$sshd_cfg")"
else
    echo "⚠️ $sshd_cfg not found; skipping permission fix."
fi


# --- Step 5: Apply Defensive Countermeasures ---
echo "=== Applying Defensive Countermeasures ==="
echo

# 1) Enable Uncomplicated Firewall (UFW)
echo "[+] Enabling UFW firewall..."
if ! command -v ufw >/dev/null 2>&1; then
    echo "[*] UFW not found — installing..."
    sudo apt-get update -y >/dev/null
    sudo apt-get install ufw -y >/dev/null
fi

# 2) Ensure SSH (port 22) is allowed
echo "[+] Allowing SSH (port 22) through firewall..."
sudo ufw allow 22/tcp comment 'Allow SSH access'

# 3) Enable UFW if not already active
if sudo ufw status | grep -q "inactive"; then
    echo "[+] Enabling UFW and setting default deny policy..."
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    yes | sudo ufw enable
else
    echo "[*] UFW is already active."
fi

# 4) Display firewall status summary
echo
echo "=== UFW Firewall Status ==="
sudo ufw status verbose
echo
echo "✅ UFW firewall enabled and SSH (port 22) allowed."
echo

# --- Step 6: Service Auditing ---
echo "=== Performing Service Auditing ==="
echo

disable_service() {
    local svc="$1"
    # Check whether a service unit exists (accept svc or svc.service)
    if systemctl list-unit-files --type=service --no-legend | awk '{print $1}' | grep -xq "${svc}.service\|${svc}"; then
        echo "[+] Disabling and stopping service: $svc"
        sudo systemctl stop "$svc" 2>/dev/null || true
        sudo systemctl disable "$svc" 2>/dev/null || true
        sudo systemctl mask "$svc" 2>/dev/null || true
    else
        echo "[*] Service $svc not found or not installed."
    fi
}

# Disable specific services
disable_service "nginx"
disable_service "ircd"
disable_service "smbd"

# Verify status
echo
echo "=== Service Status Verification ==="
for svc in nginx ircd smbd; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        echo "⚠️  $svc is still enabled!"
    else
        echo "✅ $svc is disabled."
    fi
done
echo
echo "✅ Service auditing complete."
echo

# --- Step 7: Apply OS Updates ---
echo "=== Applying OS Updates ==="
echo

echo "[+] Updating package lists..."
sudo apt-get update -y >/dev/null

# Define target packages
packages=(linux-image-generic bash busybox-static apt)

for pkg in "${packages[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "[+] Updating package: $pkg"
        sudo apt-get install --only-upgrade -y "$pkg" >/dev/null || {
            echo "⚠️  Failed to update $pkg — check package status manually."
        }
    else
        echo "[*] Package $pkg not found (may not be installed on this system)."
    fi
done

# --- Kernel updates ---
echo
echo "[+] Checking for kernel-related upgrades (linux-image/linux-headers/linux-generic)..."
# ensure package lists are fresh
sudo apt-get update -y >/dev/null
kernel_upgrades=$(apt list --upgradable 2>/dev/null | egrep -o '^[^/]+' | egrep 'linux-(image|headers|generic)' | sort -u || true)
if [[ -n "$kernel_upgrades" ]]; then
    echo "[+] Kernel-related upgrades available: $kernel_upgrades"
    echo "[+] Installing kernel-related packages..."
    if sudo apt-get install -y $kernel_upgrades; then
        echo "[+] Kernel packages installed. Updating grub and initramfs..."
        sudo update-grub >/dev/null 2>&1 || true
        sudo update-initramfs -u -k all >/dev/null 2>&1 || true
        echo "⚠️ A reboot is required to activate the new kernel."
        read -rp "Reboot now? (y/N): " do_reboot
        if [[ "$do_reboot" =~ ^[Yy]$ ]]; then
            sudo reboot
        else
            echo "❗ Remember to reboot later to apply the kernel update."
        fi
    else
        echo "⚠️ Failed to install kernel upgrades via apt. Please inspect apt output manually."
    fi
else
    echo "[+] No kernel-related upgrades available via apt."
fi

echo
echo "=== Verifying package versions ==="
dpkg -l linux-image-generic bash busybox-static apt 2>/dev/null | awk '/^ii/ {printf "✅ %s %s\n", $2, $3}'

echo
echo "✅ OS updates applied successfully."
echo

# --- Step 8: Application Updates ---
echo "=== Applying Application Updates ==="
echo

# Ensure package lists are current
echo "[+] Updating package lists..."
sudo apt-get update -y >/dev/null

# Define target applications
apps=(firefox thunderbird)

for app in "${apps[@]}"; do
    if dpkg -s "$app" >/dev/null 2>&1; then
        echo "[+] Updating application: $app"
        sudo apt-get install --only-upgrade -y "$app" >/dev/null || {
            echo "⚠️  Failed to update $app — please verify manually."
        }
    else
        echo "[*] Application $app not found (may not be installed on this system)."
    fi
done

# Thunderbird-specific update: detect install method and attempt to get the latest
echo
echo "--- Thunderbird specific update ---"
thunderbird_pkg="thunderbird"
if dpkg -s "$thunderbird_pkg" >/dev/null 2>&1; then
    echo "[+] Thunderbird installed via apt; attempting apt upgrade..."
    if sudo apt-get install --only-upgrade -y "$thunderbird_pkg"; then
        echo "✅ Thunderbird upgraded via apt."
    else
        echo "⚠️ apt upgrade failed or apt version is outdated. Checking snap/flatpak..."
        # continue to try snap/flatpak
    fi
fi

# If Mint blocks snap (nosnap.pref), prefer Flatpak path (Mint 21 compatible)
if [[ -f /etc/apt/preferences.d/nosnap.pref ]]; then
    echo "[*] Detected Mint 'nosnap.pref' — using Flatpak path for Thunderbird."
    # Backup profile for the invoking user if present
    target_user="${SUDO_USER:-$USER}"
    if [[ -n "$target_user" && "$target_user" != "root" ]]; then
        profile_dir="/home/$target_user/.thunderbird"
        if [[ -d "$profile_dir" ]]; then
            backup_profile="/tmp/${target_user}_thunderbird_profile_backup_$(date +%F-%H%M%S)"
            echo "[+] Backing up Thunderbird profile for $target_user to $backup_profile"
            sudo cp -a "$profile_dir" "$backup_profile" || true
        fi
    fi

    # Ensure flatpak and Flathub are available
    if ! command -v flatpak >/dev/null 2>&1; then
        echo "[+] Installing flatpak via apt"
        sudo apt-get update && sudo apt-get install -y flatpak || echo "⚠️ Failed to install flatpak"
    fi
    if ! flatpak remote-list | awk '{print $1}' | grep -xq flathub; then
        echo "[+] Adding Flathub remote"
        sudo flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo || true
    fi

    # Install or update Thunderbird via Flatpak
    if flatpak list | awk '{print $1}' | grep -xq "org.mozilla.Thunderbird"; then
        echo "[+] Updating Thunderbird Flatpak..."
        sudo flatpak update -y org.mozilla.Thunderbird || echo "⚠️ flatpak update failed; check manually."
    else
        echo "[+] Installing Thunderbird from Flathub via Flatpak..."
        sudo flatpak install -y flathub org.mozilla.Thunderbird || echo "⚠️ flatpak install failed; check manually."
    fi
else
    # If snapd available, refresh snap; otherwise offer snap (non-Mint systems)
    if command -v snap >/dev/null 2>&1; then
        if snap list | awk '{print $1}' | grep -xq "thunderbird"; then
            echo "[+] Thunderbird installed as snap; running 'snap refresh thunderbird'..."
            sudo snap refresh thunderbird || echo "⚠️ snap refresh failed; check manually."
        fi
    else
        # Offer to install snapd if apt exists and user wants to
        if command -v apt-get >/dev/null 2>&1; then
            echo "[*] snapd not present. To get the latest Thunderbird you can install the snap package." 
            read -rp "Install snapd and switch to Thunderbird snap? (y/N): " install_snap
            if [[ "$install_snap" =~ ^[Yy]$ ]]; then
                sudo apt-get update && sudo apt-get install snapd -y
                sudo systemctl enable --now snapd
                sudo ln -s /var/lib/snapd/snap /snap 2>/dev/null || true
                sudo snap install thunderbird
            fi
        fi
    fi

    # Flatpak fallback
    if command -v flatpak >/dev/null 2>&1; then
        if flatpak list | awk '{print $1}' | grep -xq "org.mozilla.Thunderbird"; then
            echo "[+] Thunderbird installed via Flatpak; updating..."
            sudo flatpak update -y org.mozilla.Thunderbird || echo "⚠️ flatpak update failed; check manually."
        fi
    fi
fi

echo
echo "=== Verifying application versions ==="
dpkg -l firefox thunderbird 2>/dev/null | awk '/^ii/ {printf "✅ %s %s\n", $2, $3}'

echo
echo "✅ Application updates applied successfully."
echo

# --- Step 9: Prohibited Files Cleanup ---
echo "=== Scanning for Prohibited Media Files ==="
echo

# Directories to scan — adjust as needed
scan_dirs=("/home" "/opt" "/var" "/tmp")

echo "[+] Searching for prohibited MP3 and OGG files..."
mapfile -t prohibited_files < <(sudo find "${scan_dirs[@]}" -xdev -type f \( -iname "*.mp3" -o -iname "*.ogg" \) 2>/dev/null)

if ((${#prohibited_files[@]} == 0)); then
    echo "✅ No prohibited audio files (.mp3 or .ogg) found."
else
    ts=$(date +%F-%H%M%S)
    backup_media_dir="/tmp/prohibited_media_backup_$ts"
    echo "⚠️  Found ${#prohibited_files[@]} prohibited files. Backing up to $backup_media_dir and removing originals..."
    sudo mkdir -p "$backup_media_dir"
    for file in "${prohibited_files[@]}"; do
        # preserve directory structure under the backup dir
        rel_dir=$(dirname "$file")
        dest="$backup_media_dir$rel_dir"
        sudo mkdir -p "$dest"
        sudo cp -a "$file" "$dest/" 2>/dev/null || true
        # Try to remove immutable attribute if present, then delete
        if sudo chattr -i "$file" 2>/dev/null; then
            echo "[+] Removed immutable attribute from $file"
        fi
        parent_dir=$(dirname "$file")
        if sudo chattr -i "$parent_dir" 2>/dev/null; then
            echo "[+] Removed immutable attribute from directory $parent_dir"
        fi
        if sudo rm -f "$file" 2>/dev/null; then
            echo "Deleted: $file"
        else
            echo "⚠️ Failed to delete: $file — attempting to show diagnostic info:" 
            sudo ls -l "$file" || true
            sudo lsattr "$file" || true
            sudo stat "$file" || true
            # attempt removal again showing errors
            sudo rm -f "$file" || echo "⚠️ Still could not remove $file"
        fi
    done
    echo "✅ Prohibited media files backed up to $backup_media_dir and removed where possible."
fi

echo
echo "=== Prohibited file scan complete ==="
echo

# --- Step 10: Remove Unwanted Software ---
echo "=== Removing Unwanted Packages ==="
echo

unwanted=(hydra nbtscan p0f manaplus packit)
installed=()

# Detect which unwanted packages are installed
for pkg in "${unwanted[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        installed+=("$pkg")
    fi
done

if ((${#installed[@]} == 0)); then
    echo "✅ None of the specified unwanted packages are installed."
else
    echo "⚠️  The following unwanted packages are installed:"
    printf ' - %s\n' "${installed[@]}"
    echo
    read -rp "Remove and purge these packages now? (y/n): " confirm_remove
    if [[ "$confirm_remove" =~ ^[Yy]$ ]]; then
        echo "[+] Removing packages..."
        sudo apt-get update -y >/dev/null

        # Try to fix any broken dependencies before removing packages
        echo "[+] Checking for broken packages and attempting repair..."
        if ! sudo apt-get -f install -y >/dev/null 2>&1; then
            echo "⚠️ 'apt-get -f install' failed; attempting 'apt --fix-broken install' and showing output..."
            if ! sudo apt --fix-broken install -y; then
                echo "❌ Could not automatically fix broken packages. Please run 'sudo apt --fix-broken install' manually and re-run this script."
                exit 1
            fi
        fi

        for pkg in "${installed[@]}"; do
            echo "Removing: $pkg"
            if sudo apt-get remove --purge -y "$pkg" >/dev/null 2>&1; then
                echo "Removed: $pkg"
            else
                echo "⚠️ Failed to remove: $pkg — attempting to fix dependencies and retry once..."
                sudo apt --fix-broken install -y || true
                if sudo apt-get remove --purge -y "$pkg"; then
                    echo "Removed on retry: $pkg"
                else
                    echo "⚠️ Still failed to remove: $pkg; showing apt output:" 
                    sudo apt-get remove --purge -y "$pkg" || true
                fi
            fi
        done
        echo
        echo "[+] Cleaning up orphaned packages..."
        sudo apt-get autoremove -y >/dev/null
        sudo apt-get autoclean -y >/dev/null
        echo "✅ Unwanted package removal complete."
    else
        echo "❎ No packages were removed."
    fi
fi

echo

# --- Step 11: Remove Known Backdoors (netcat, dispatcher.py, kworker-like malicious files) ---
echo "=== Step 11: Scan & Remove Suspected Backdoors ==="
echo

ts=$(date +%F-%H%M%S)
backup_dir="/tmp/backdoor_removal_backup_$ts"
sudo mkdir -p "$backup_dir"

# Helper to safely remove a file after backing it up
safe_remove_file() {
    local f="$1"
    echo "[+] Backing up: $f -> $backup_dir/"
    sudo mkdir -p "$backup_dir/$(dirname "${f#/}")"
    sudo cp -a "$f" "$backup_dir/$(dirname "${f#/}")/" 2>/dev/null || true
    echo "[+] Removing: $f"
    sudo rm -f "$f" && echo "Removed: $f" || echo "⚠️ Failed to remove: $f"
}

# 1) Find suspicious netcat/netcat-like binaries (but avoid known system nc)
echo "[+] Searching for suspicious 'netcat'/'nc' binaries (excluding system packages)..."
mapfile -t suspicious_nc < <(sudo find / -type f \( -iname "*netcat*" -o -iname "*nc" -o -iname "nc.*" \) 2>/dev/null | \
    egrep -v "^/bin/|^/usr/bin/|^/usr/sbin/|^/sbin/|^/lib" || true)

if ((${#suspicious_nc[@]} == 0)); then
    echo "✅ No suspicious netcat-like files found outside standard system paths."
else
    echo "⚠️ Found suspicious netcat-like files:"
    printf '%s\n' "${suspicious_nc[@]}"
    read -rp "Remove these suspicious netcat files? (y/N): " confirm_nc
    if [[ "$confirm_nc" =~ ^[Yy]$ ]]; then
        for f in "${suspicious_nc[@]}"; do
            safe_remove_file "$f"
        done
    else
        echo "⏭ Skipping removal of netcat-like files."
    fi
fi
echo

# 2) Find dispatcher.py (common python backdoor name) anywhere
echo "[+] Searching for 'dispatcher.py' files..."
mapfile -t dispatcher_files < <(sudo find / -type f -iname "dispatcher.py" 2>/dev/null || true)

if ((${#dispatcher_files[@]} == 0)); then
    echo "✅ No dispatcher.py files found."
else
    echo "⚠️ Found dispatcher.py files:"
    printf '%s\n' "${dispatcher_files[@]}"
    read -rp "Remove these dispatcher.py files? (y/N): " confirm_disp
    if [[ "$confirm_disp" =~ ^[Yy]$ ]]; then
        for f in "${dispatcher_files[@]}"; do
            safe_remove_file "$f"
        done
    else
        echo "⏭ Skipping removal of dispatcher.py files."
    fi
fi
echo

# 3) Detect files named 'kworker' or suspicious user-space binaries masquerading as kworker
echo "[+] Searching for regular files named 'kworker' (not kernel threads)..."
mapfile -t kworker_files < <(sudo find / -type f -iname "kworker*" 2>/dev/null | \
    egrep -v "^/usr/lib/|^/lib/|^/bin/|^/usr/bin/" || true)

if ((${#kworker_files[@]} == 0)); then
    echo "✅ No suspicious 'kworker' files found in user-space locations."
else
    echo "⚠️ Found suspicious kworker-named files:"
    printf '%s\n' "${kworker_files[@]}"
    read -rp "Remove these suspicious kworker files? (y/N): " confirm_kwf
    if [[ "$confirm_kwf" =~ ^[Yy]$ ]]; then
        for f in "${kworker_files[@]}"; do
            # Attempt to stop any process using this file before removal
            pids_using=$(sudo lsof -t "$f" 2>/dev/null || true)
            if [[ -n "$pids_using" ]]; then
                echo "[+] Processes using $f: $pids_using"
                read -rp "Kill those processes before removing file? (y/N): " killprocs
                if [[ "$killprocs" =~ ^[Yy]$ ]]; then
                    for p in $pids_using; do
                        # Skip kernel threads (they appear in brackets in ps -o comm)
                        comm=$(ps -p "$p" -o comm= 2>/dev/null || echo "")
                        if [[ "$comm" =~ ^\[.*\]$ ]]; then
                            echo "⚠️ Skipping kernel thread pid $p ($comm)."
                            continue
                        fi
                        echo "[+] Killing pid $p"
                        sudo kill -9 "$p" 2>/dev/null || echo "⚠️ Failed to kill pid $p"
                    done
                else
                    echo "⏭ Not killing processes; file removal may fail."
                fi
            fi
            safe_remove_file "$f"
        done
    else
        echo "⏭ Skipping removal of suspicious kworker files."
    fi
fi
echo

# 4) Extra: look for running netcat listeners and suspicious listeners on high ports (common backdoor pattern)
echo "[+] Scanning for listening processes that look like netcat/backdoors..."
mapfile -t listeners < <(sudo ss -tulnp 2>/dev/null | egrep -i 'nc|netcat|python|perl' || true)
if ((${#listeners[@]})); then
    printf '%s\n' "${listeners[@]}"
    read -rp "Attempt to stop/kill suspicious listening processes shown above? (y/N): " confirm_listen_kill
    if [[ "$confirm_listen_kill" =~ ^[Yy]$ ]]; then
        # extract pids from the ss output lines
        for line in "${listeners[@]}"; do
            # try to extract pid using awk
            pid=$(echo "$line" | awk -F',' '{for(i=1;i<=NF;i++) if($i ~ /pid=/) {gsub(/[^0-9]/,"",$i); print $i}}')
            # fallback: use lsof for the port
            if [[ -z "$pid" ]]; then
                pid=$(echo "$line" | awk '{print $6}' | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
            fi
            if [[ -n "$pid" ]]; then
                # ensure not a kernel thread
                comm=$(ps -p "$pid" -o comm= 2>/dev/null || echo "")
                if [[ "$comm" =~ ^\[.*\]$ ]]; then
                    echo "⚠️ Skipping kernel thread pid $pid ($comm)."
                    continue
                fi
                echo "[+] Killing suspicious listener pid $pid ($comm)"
                sudo kill -9 "$pid" 2>/dev/null || echo "⚠️ Failed to kill pid $pid"
            fi
        done
    else
        echo "⏭ Skipping process termination for listeners."
    fi
else
    echo "✅ No obvious netcat/python/perl listeners found by ss."
fi
echo

echo "=== Backdoor removal step complete. Backups are in: $backup_dir"
echo "⚠️ Review $backup_dir before purging to ensure no legitimate files were removed by mistake."
echo

# --- Step 12: Secure SSH Configuration ---
echo "=== Step 12: Applying SSH Application Security Settings ==="
echo

sshd_config="/etc/ssh/sshd_config"
backup="/etc/ssh/sshd_config.backup.$(date +%F-%H%M%S)"

echo "[+] Backing up SSH configuration to $backup"
sudo cp -a "$sshd_config" "$backup"

# 1) Disable root login
echo "[+] Disabling SSH root login..."
sudo sed -i '/^PermitRootLogin/d' "$sshd_config"
echo "PermitRootLogin no" | sudo tee -a "$sshd_config" >/dev/null

# 2) Disable SSH forwarding of network traffic
echo "[+] Disabling SSH forwarding (X11, TCP, Agent)..."
sudo sed -i '/^AllowTcpForwarding/d' "$sshd_config"
sudo sed -i '/^X11Forwarding/d' "$sshd_config"
sudo sed -i '/^AllowAgentForwarding/d' "$sshd_config"
cat <<'EOF' | sudo tee -a "$sshd_config" >/dev/null
AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no
EOF

# 3) Prevent users from setting custom environment variables
echo "[+] Disabling SSH environment variable overrides..."
sudo sed -i '/^PermitUserEnvironment/d' "$sshd_config"
echo "PermitUserEnvironment no" | sudo tee -a "$sshd_config" >/dev/null

# 4) Limit login time (LoginGraceTime)
echo "[+] Limiting SSH login grace time..."
sudo sed -i '/^LoginGraceTime/d' "$sshd_config"
echo "LoginGraceTime 30" | sudo tee -a "$sshd_config" >/dev/null

# 5) Limit login attempts (MaxAuthTries)
echo "[+] Limiting SSH authentication attempts..."
sudo sed -i '/^MaxAuthTries/d' "$sshd_config"
echo "MaxAuthTries 3" | sudo tee -a "$sshd_config" >/dev/null

# Reload SSH service to apply settings
echo "[+] Reloading SSH service..."
sudo systemctl reload ssh || sudo systemctl restart ssh

echo
echo "✅ SSH security hardening applied successfully."
echo "Settings enforced:"
echo " - Root login disabled"
echo " - Forwarding disabled (X11, TCP, Agent)"
echo " - User environment variable overrides disabled"
echo " - Login grace time limited to 30 seconds"
echo " - Max authentication attempts set to 3"
echo

#Hello
