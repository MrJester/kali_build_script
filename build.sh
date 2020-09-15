#!/usr/bin/env bash

#**************************************************************************#
#  Filename: build.sh                   (Created: 2019-03-26)              #
#                                       (Updated: 2019-04-15)              #
#  Info:                                                                   #
#    Kali kick start script for adding missing tools and configs           #
#  Author:                                                                 #
#    Ryan Hays                                                             #
#**************************************************************************#
# TODO:
#   Update User-Agents on common tools
#       Nmap
#       Nikto


# Setup a log file to catch all output
exec > >(tee -ia /root/Desktop/build_log.log)
exec 2> >(tee -ia /root/Desktop/build_err_log.log)


##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal


##### Setup some global vars
STAGE=0
TOTAL=$(grep '(${STAGE}/${TOTAL})' $0 | wc -l);(( TOTAL-- ))
STARTTIME=$(date +%s)
KALINAME="Kiosk-$(shuf -i 1-1000 -n 1)"
export STAGING_KEY="RANDOM"
export DEBIAN_FRONTEND="noninteractive"


##### PRE CHECKS #####
##### Check if we are running as root - else this script will fail (hard!)
if [[ "${EUID}" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" This script must be ${RED}run as root${RESET}" 1>&2
  echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
  sleep 10
  exit 1
else
  echo -e " ${BLUE}[*]${RESET} ${BOLD}Kali Build Script${RESET}"
  sleep 3
fi

##### Fix display output for GUI programs (when connecting via SSH)
export DISPLAY=:0.0
export TERM=xterm

##### Change nameserver
sed -i "s/deb http:\/\/http.kali.org\/kali kali-rolling main contrib non-free/deb https:\/\/http.kali.org\/kali kali-rolling main contrib non-free/" /etc/apt/sources.list

(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}hostname${RESET}"
echo $KALINAME > /etc/hostname
sed -i "s/kali/$KALINAME/g" /etc/hosts

(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Fixing ${GREEN}Client SSH Config${RESET}"
cp ssh_config /etc/ssh/

##### Install OS updates
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}Operating System${RESET}"
# Setup some variables so we don't get bothered with questions during the updates
# These are old and not needed any more. Will remove after further testing
#echo 'wireshark-common wireshark-common/install-setuid boolean false'| debconf-set-selections
#echo 'libpam0g libraries/restart-without-asking boolean	true'| debconf-set-selections
#echo 'libpam0g:amd64 libraries/restart-without-asking boolean	true'| debconf-set-selections
#echo 'libpam0g libpam0g/restart-failed string'| debconf-set-selections
#echo 'libpam0g:amd64 libpam0g/restart-failed string'| debconf-set-selections
#echo 'libpam0g libpam0g/restart-services string'| debconf-set-selections
#echo 'libpam0g:amd64 libpam0g/restart-services string'| debconf-set-selections
#echo 'libpam0g libpam0g/xdm-needs-restart string'| debconf-set-selections
#echo 'libpam0g:amd64 libpam0g/xdm-needs-restart string'| debconf-set-selections

##### Update Packages
if ! apt -qq update; then
  echo -e "\n\n ${RED}[!]${RESET} There was an ${RED}issue accessing network repositories${RESET}"
  echo -e "\n\n ${YELLOW}[i]${RESET} Are you connected to a network and is the internet accessible??"
  exit 1
fi

apt-get -qq -y upgrade && apt-get -qq -y dist-upgrade && apt-get -qq -y autoremove

##### Install git - all users
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}git${RESET} ~ revision control"
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#--- Set as default editor
git config --global core.editor "vim"
#--- Set as default mergetool
git config --global merge.tool vimdiff
git config --global merge.conflictstyle diff3
git config --global mergetool.prompt false
#--- Set as default push
git config --global push.default simple
#-- Set default username and email
git config --global user.email "hays.ryan@gmail.com"
git config --global user.name "MrJester"

##### Check to see if Kali is in a VM. If so, install "Virtual Machine Addons/Tools" for a "better" virtual experiment
if (dmidecode | grep -iq vmware); then
##### Install virtual machines tools ~ http://docs.kali.org/general-use/install-vmware-tools-kali-guest
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}VMware's virtual machine tools${RESET}"
apt-get -y -qq install open-vm-tools-desktop fuse \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
elif (dmidecode | grep -iq virtualbox); then
##### Installing Virtualbox Guest Additions.   Note: Need VirtualBox 4.2.xx+ for the host (http://docs.kali.org/general-use/kali-linux-virtual-box-guest)
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}VirtualBox's guest additions${RESET}"
apt-get -y -qq install virtualbox-guest-x11 \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
fi

##### Create Logging directory requirements
(( STAGE++ )); echo -e " ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Establishing ${GREEN}logging directory requirements${RESET}"
if [[ -d /data/logs ]]; then
    echo -e "${RED}[!] Logging directory already exists${RESET}"
else
    mkdir -p /data/logs
fi

##### Configuring
(( STAGE++ )); echo -e " ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}custom terminal${RESET}"
# Custom fonts
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/ryanoasis/nerd-fonts.git /tmp/nerd-fonts/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /tmp/nerd-fonts/ >/dev/null
git pull -q
chmod +x install.sh
./install.sh
popd >/dev/null

# Changing shell to zsh
runuser -l $(logname) -c 'chsh -s /usr/bin/zsh'
chsh -s /usr/bin/zsh

# Tweak Terminal Appearance
cp zshrc /home/$(logname)/.zshrc
cp zshrc /root/.zshrc

# Setup script to rotate hostname and set up crontab to be performed each reboot
cat >> /usr/local/bin/update-hostname.sh << EOF
#!/usr/bin/bash

OLDHOST=$(cat /etc/hostname)
KALINAME="Kiosk-$(shuf -i 1-1000 -n 1)"
echo $KALINAME > /etc/hostname
sed -i "s/$OLDHOST/$KALINAME/g" /etc/hosts
hostname $KALINAME
EOF
chmod +x /usr/local/bin/update-hostname.sh
(crontab -l 2>/dev/null; echo "@reboot /usr/local/bin/update-hostname.sh") | crontab -

##### Reconfigure SSH Server
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}OpenSSH Server${RESET}"
systemctl stop ssh 1>&2
mkdir /etc/ssh/default_keys
mv /etc/ssh/ssh_host_* /etc/ssh/default_keys/
dpkg-reconfigure openssh-server 1>&2
systemctl enable ssh 1>&2
systemctl start ssh 1>&2

##### Configure Postgresql to start
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}Postgresql${RESET}"
systemctl enable postgresql
systemctl start postgresql

##### Configure Metasploit DB
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}Metasploit${RESET}"
msfdb init

##### SOFTWARE INSTALLS #####
##### Install simple file browser/upload
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Install ${GREEN}Simple File Upload${RESET}"
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/MrJester/file_browser.git /opt/file_browser/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/file_browser/ >/dev/null
git pull -q
pip3 install -r requirements.txt 1>&2
ln -s /opt/file_browser/filebrowser.py /usr/local/bin/file-browser.py
chmod +x /usr/local/bin/file-browser.py
popd >/dev/null

##### Install JQ
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Install ${GREEN}JQ${RESET}"
apt-get -y -qq install jq \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2

##### Install Veil Evasion
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Veil-Evasion Framework${RESET} ~ AV Evasion Tool"
dpkg --add-architecture i386 1>&2
apt-get update 1>&2
apt-get -y -qq install wine32 veil-evasion \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
/usr/share/veil/config/setup.sh --force --silent 1>&2

##### Install spraywmi
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}SprayWMI${RESET} ~ WMI executition of PowerShell code to expand influence"
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/trustedsec/spraywmi.git /opt/spraywmi/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/spraywmi/ >/dev/null
git pull -q 1>&2
popd >/dev/null\

##### Install Unicorn
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}TrustedSec Unicorn${RESET} ~ PowerShell metasploit payloads"
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/trustedsec/unicorn.git /opt/unicorn/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/unicorn/ >/dev/null
git pull -q 1>&2
popd >/dev/null

##### Install Domainhunter
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}DomainHunter${RESET} ~ Domain OSINT Tool"
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/minisllc/domainhunter.git /opt/domainhunter/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/domainhunter/ >/dev/null
git pull -q 1>&2
pip3 install -r requirements.txt 1>&2
python3 setup.py install 1>&2
popd >/dev/null

##### Install esedbexport
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}esedbexport${RESET} ~ Tool to extract various credentials and secrets from Windows registry hives"
apt-get -y install git autoconf automake autopoint libtool pkg-config build-essential \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/libyal/libesedb.git /tmp/libesedb/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /tmp/libesedb/ >/dev/null
./synclibs.sh 1>&2
./autogen.sh 1>&2
./configure 1>&2
make 1>&2
make install 1>&2
ldconfig 1>&2
popd >/dev/null

##### Install NTDSXtract
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}NTDSXtract${RESET} ~ Extract information from the Microsoft Active Directory"
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/csababarta/ntdsxtract.git /tmp/ntdsxtract/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /tmp/ntdsxtract/ >/dev/null
git pull -q
python setup.py install
popd >/dev/null

##### Update Nmap scripts
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}NMap Script${RESET}"
nmap --script-updatedb >/dev/null
pushd /usr/share/nmap/scripts/ >/dev/null
wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse >/dev/null
git clone -q -b master https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2

##### Install Atom Text Editor
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}NTDSXtract${RESET} ~ Extract information from the Microsoft Active Directory"
apt-get -y -qq install libgconf-2-4 gconf2 gconf2-common gconf-service gvfs-bin \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
wget -L -O '/tmp/atom.deb' https://atom.io/download/deb  >/dev/null
dpkg -i /tmp/atom.deb

##### Install Bettercap
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Bettercap${RESET}"
apt-get -y -qq install build-essential ruby-dev libpcap-dev bettercap \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2

##### Install GoPhish
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}GoPhish${RESET}"
wget -L -O '/tmp/gophish.zip' https://github.com/gophish/gophish/releases/download/v0.11.0/gophish-v0.11.0-linux-64bit.zip  >/dev/null
unzip /tmp/gophish.zip -d /opt/gophish/ 1>&2

##### Install Windows Exploit Suggester
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Windows Exploit Suggester${RESET}"
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/bitsadmin/wesng.git /opt/wesng/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/wesng/ >/dev/null
git pull -q 1>&2
python wes.py --update 1>&2
popd >/dev/null

##### Install ftp client
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}FTP client${RESET}"
apt-get -y -qq install ftp \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2

##### Install FindFrontableDomains
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}FindFrontableDomains${RESET}"
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/rvrsh3ll/FindFrontableDomains.git /opt/FindFrontableDomains/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/FindFrontableDomains/ >/dev/null
git pull -q
./setup.sh 1>&2
popd >/dev/null

##### Install Vulmap
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Vulmap${RESET}"
apt-get -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/vulmon/Vulmap.git /opt/Vulmap/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/Vulmap/ >/dev/null
git pull -q
popd >/dev/null

##### Update wordlists
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Updating${RESET} wordlists"
apt-get -y -qq install seclists \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/berzerk0/Probable-Wordlists.git /usr/share/wordlists/Probable-Wordlists \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /usr/share/wordlists/Probable-Wordlists >/dev/null
git pull -q
popd >/dev/null

##### Update searchsploit
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Updating${RESET} searchsploit"
searchsploit --update 1>&2

##### Install OpenVAS
#(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Installing${RESET} OpenVAS"
#apt-get -y -qq install openvas-scanner openvas \
#|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
#/usr/bin/openvas-setup 1>&2
#--- Make sure all services are correct
#openvas-start
#--- User control
#username="root"
#password="SuperSecretPassword"
#(openvasmd --get-users | grep -q ^admin$) \
#  && echo -n 'admin user: ' \
#  && openvasmd --delete-user=admin
#(openvasmd --get-users | grep -q "^${username}$") \
#  || (echo -n "${username} user: "; openvasmd --create-user="${username}"; openvasmd --user="${username}" --new-password="${password}" >/dev/null)
#echo -e " ${YELLOW}[i]${RESET} OpenVAS username: ${username}"
#echo -e " ${YELLOW}[i]${RESET} OpenVAS password: ${password}   ***${BOLD}CHANGE THIS ASAP${RESET}***"
#echo -e " ${YELLOW}[i]${RESET} Run: # openvasmd --user=root --new-password='<NEW_PASSWORD>'"

##### CLEANUP #####
##### Clean the system
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Cleaning${RESET} the system"
#--- Clean package manager
for FILE in clean autoremove; do apt-get -y -qq "${FILE}"; done
apt-get -y -qq purge $(dpkg -l | tail -n +6 | egrep -v '^(h|i)i' | awk '{print $2}')   # Purged packages
#--- Update slocate database
updatedb
#--- Reset folder location
cd ~/ &>/dev/null
#--- Remove any history files (as they could contain sensitive info)
history -c 2>/dev/null
for i in $(cut -d: -f6 /etc/passwd | sort -u); do
[ -e "${i}" ] && find "${i}" -type f -name '.*_history' -delete
done

##### Time taken
FINISHTIME=$(date +%s)
echo -e "\n\n ${YELLOW}[i]${RESET} Time (roughly) taken: ${YELLOW}$(( $(( FINISHTIME - STARTTIME )) / 60 )) minutes${RESET}"

echo -e "\n\n ${YELLOW}[i]${RESET} Please reboot the system now to ensure all changes are taken. ${YELLOW}${RESET}"