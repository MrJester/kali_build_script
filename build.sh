#!/usr/bin/env bash

#**************************************************************************#
#  Filename: build.sh                   (Created: 2019-03-26)              #
#                                       (Updated: 2019-03-27)              #
#  Info:                                                                   #
#    Kali kick start script for adding missing tools and configs           #
#  Author:                                                                 #
#    Ryan Hays                                                             #
#**************************************************************************#

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

##### Check Internet access
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Checking ${GREEN}Internet access${RESET}"
#--- Can we ping google?
for i in {1..10}; do ping -c 1 -W ${i} www.google.com &>/dev/null && break; done
#--- Run this, if we can't
if [[ "$?" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?)" 1>&2
  echo -e ' '${RED}'[!]'${RESET}" Will try and use ${YELLOW}DHCP${RESET} to 'fix' the issue" 1>&2
  chattr -i /etc/resolv.conf 2>/dev/null
  dhclient -r
  #--- Second interface causing issues?
  ip addr show eth1 &>/dev/null
  [[ "$?" == 0 ]] \
    && route delete default gw 192.168.155.1 2>/dev/null
  #--- Request a new IP
  dhclient
  dhclient eth0 2>/dev/null
  dhclient wlan0 2>/dev/null
  dhclient eth1 2>/dev/null
  #--- Wait and see what happens
  sleep 15s
  _TMP="true"
  _CMD="$(ping -c 1 8.8.8.8 &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == "true" ]]; then
    _TMP="false"
    echo -e ' '${RED}'[!]'${RESET}" ${RED}No Internet access${RESET}" 1>&2
    echo -e ' '${RED}'[!]'${RESET}" You will need to manually fix the issue, before re-running this script" 1>&2
    sleep 10
    exit 1
  fi
  _CMD="$(ping -c 1 www.google.com &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == "true" ]]; then
    _TMP="false"
    echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?)" 1>&2
    echo -e ' '${RED}'[!]'${RESET}" You will need to manually fix the issue, before re-running this script" 1>&2
    sleep 10
    exit 1
  fi
  if [[ "$_TMP" == "false" ]]; then
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} VM Detected"
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Try switching network adapter mode${RESET} (e.g. NAT/Bridged)"
    echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
    sleep 10
    exit 1
  fi
else
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Detected Internet access${RESET}" 1>&2
fi

##### GitHub under DDoS?
######## CHECK THIS FUNCTION
#(( STAGE++ )); echo -e " ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Checking ${GREEN}GitHub status${RESET}"
#timeout 300 curl --progress -k -L -f "https://kctbh9vrtdwd.statuspage.io/api/v2/status.json" >/dev/null | grep -q "All Systems Operational" \
#  || (echo -e ' '${RED}'[!]'${RESET}" ${RED}GitHub is currently having issues${RESET}. ${BOLD}Lots may fail${RESET}. See: https://status.github.com/" 1>&2 \
#&& sleep 10 && exit 1)

##### UPDATES AND CONFIGS #####
##### Disable its auto notification package updater
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Disabling GNOME's ${GREEN}notification package updater${RESET} service ~ in case it runs during this script"
timeout 5 killall -w /usr/lib/apt/methods/http >/dev/null 2>&1

(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring GNOME's ${GREEN}settings${RESET}"
gsettings set org.gnome.desktop.screensaver lock-enabled false
gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0
gsettings set org.gnome.desktop.session idle-delay 0

(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}hostname${RESET}"
echo $KALINAME > /etc/hostname
sed -i "s/kali/$KALINAME/g" /etc/hosts

##### Install OS updates
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}Operating System${RESET}"
apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y

##### Install git - all users
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}git${RESET} ~ revision control"
apt -y -qq install git \
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
git config --global user.email "root@kali"
git config --global user.name "root"

##### Check to see if Kali is in a VM. If so, install "Virtual Machine Addons/Tools" for a "better" virtual experiment
if (dmidecode | grep -iq vmware); then
##### Install virtual machines tools ~ http://docs.kali.org/general-use/install-vmware-tools-kali-guest
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}VMware's virtual machine tools${RESET}"
apt -y -qq install open-vm-tools-desktop fuse \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
elif (dmidecode | grep -iq virtualbox); then
##### Installing Virtualbox Guest Additions.   Note: Need VirtualBox 4.2.xx+ for the host (http://docs.kali.org/general-use/kali-linux-virtual-box-guest)
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}VirtualBox's guest additions${RESET}"
apt -y -qq install virtualbox-guest-x11 \
  || echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
fi

##### Create Logging directory requirements
(( STAGE++ )); echo -e " ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Establishing ${GREEN}logging directory requirements${RESET}"
if [[ -d /data/logs ]]; then
    echo -e "${RED}[!] Logging directory already exists${RESET}"
else
    mkdir -p /data/logs
fi
if [[ -d /data/logs/script ]]; then
    echo -e "${RED}[!] Script directory already exists${RESET}"
else
    mkdir -p /data/logs/script
fi

if [[ -d /data/logs/screenshots ]]; then
    echo -e "${RED}[!] Screenshot directory already exists${RESET}"
else
    mkdir -p /data/logs/screenshots
fi

##### Create Logging directory requirements
(( STAGE++ )); echo -e " ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Adding ${GREEN}Timestamp to terminal and history${RESET}"
echo 'export HISTTIMEFORMAT="%F-%T "' >> /root/.bashrc
echo 'export PS1="\e[032m\D{%F %T}\e[m \n\u \W\\$ \[$(tput sgr0)\]"' >> /root/.bashrc
echo 'lsof -tac script "$(tty)" || {' >> /root/.bashrc
echo '   	script -f /data/logs/script/Script-$(date -d "today" +"%Y%m%d%H%M%S").log' >> /root/.bashrc
echo '}' >>  /root/.bashrc
echo 'spool /root/msf_console.log' > /usr/share/metasploit-framework/scripts/resource/snrt.rc
echo 'use exploit/multi/handler' >> /usr/share/metasploit-framework/scripts/resource/snrt.rc
echo 'set ExitOnSession false' >> /usr/share/metasploit-framework/scripts/resource/snrt.rc
apt -y -qq install scrot \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
touch /usr/local/bin/screen.sh
chmod 777 /usr/local/bin/screen.sh
cat >> /root/archive.sh << EOF
#!/bin/sh
tar -czf /data/logs/screenshots/screenshot_backup_`date +%Y%m%d%H%M%S`.tar.gz /data/logs/screenshots/*.png && rm -rf /data/logs/screenshots/*.png
tar -czf /data/logs/script/script_backup_`date +%Y%m%d%H%M%S`.tar.gz /data/logs/script/*.log && rm -rf /data/logs/script/*.log
EOF
chmod +x /root/archive.sh
(crontab -l 2>/dev/null; echo "0 * * * * /root/archive.sh") | crontab -

##### Setting up Bash Aliases
(( STAGE++ )); echo -e " ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Building ${GREEN}Bash Aliases${RESET}"
cat >> /root/.bash_aliases << EOF
## grep aliases
alias grep="grep --color=always"
alias ngrep="grep -n"

alias egrep="egrep --color=auto"

alias fgrep="fgrep --color=auto"

## Checksums
alias sha1="openssl sha1"
alias md5="openssl md5"

## List open ports
alias ports="netstat -tulanp"

## Get external IP address
alias ipx="curl -s http://ipinfo.io/ip"

## Directory navigation aliases
alias ..="cd .."
alias ...="cd ../.."
alias ....="cd ../../.."
alias .....="cd ../../../.."

## Update the OS
alias update-os='apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y && apt autoremove -y'

## Extract file
## Extract file, example. "ex package.tar.bz2"
ex() {
  if [[ -f \$1 ]]; then
    case \$1 in
      *.tar.bz2) tar xjf \$1 ;;
      *.tar.gz)  tar xzf \$1 ;;
      *.bz2)     bunzip2 \$1 ;;
      *.rar)     rar x \$1 ;;
      *.gz)      gunzip \$1  ;;
      *.tar)     tar xf \$1  ;;
      *.tbz2)    tar xjf \$1 ;;
      *.tgz)     tar xzf \$1 ;;
      *.zip)     unzip \$1 ;;
      *.Z)       uncompress \$1 ;;
      *.7z)      7z x \$1 ;;
      *)         echo \$1 cannot be extracted ;;
    esac
  else
    echo \$1 is not a valid file
  fi
}

## openvas
alias openvas="openvas-stop; openvas-start; sleep 3s; xdg-open https://127.0.0.1:9392/ >/dev/null 2>&1"
EOF

cat >> /usr/local/bin/update-hostname.sh << EOF
!#/usr/bin/bash

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
systemctl stop ssh.service
mkdir /etc/ssh/default_keys
mv /etc/ssh/ssh_host_* /etc/ssh/default_keys/
dpkg-reconfigure openssh-server
systemctl enable ssh.service
systemctl start ssh.service

##### Configure Postgresql to start
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}Postgresql${RESET}"
systemctl enable postgresql
service postgresql start

##### Configure Metasploit DB
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}Metasploit${RESET}"
msfdb init

##### SOFTWARE INSTALLS #####
##### Install simple file upload
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Install ${GREEN}Simple File Upload${RESET}"
cat >> /usr/local/bin/file_upload.py << EOF
#!/usr/local/bin/env python
import os
from flask import Flask, request, redirect, url_for
from werkzeug import secure_filename

UPLOAD_FOLDER = '/tmp/'
ALLOWED_EXTENSIONS = set(['txt', 'zip'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('index'))
    return """
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form action="" method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>
    <p>%s</p>
    """ % "<br>".join(os.listdir(app.config['UPLOAD_FOLDER'],))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)
EOF

##### Install Veil Evasion
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Veil-Evasion Framework${RESET} ~ AV Evasion Tool"
apt -y -qq install veil-evasion \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
/usr/share/veil/config/setup.sh --force --silent 1>&2

##### Install Empire
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Empire${RESET} ~ PowerShell post-exploitation"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/PowerShellEmpire/Empire.git /opt/empire/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/empire/ >/dev/null
/opt/empire/setup/install.sh
git pull -q
popd >/dev/null

##### Install spraywmi
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}SprayWMI${RESET} ~ WMI executition of PowerShell code to expand influence"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/trustedsec/spraywmi.git /opt/spraywmi/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/spraywmi/ >/dev/null
git pull -q
popd >/dev/null

##### Install Impacket
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Impacket${RESET} ~ Useful pentesting tools"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/CoreSecurity/impacket.git /opt/impacket/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/impacket/ >/dev/null
git pull -q
python setup.py install
popd >/dev/null

##### Install Unicorn
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}TrustedSec Unicorn${RESET} ~ PowerShell metasploit payloads"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/trustedsec/unicorn.git /opt/unicorn/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/unicorn/ >/dev/null
git pull -q
popd >/dev/null

##### Install Domainhunter
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}DomainHunter${RESET} ~ Domain OSINT Tool"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/minisllc/domainhunter.git /opt/domainhunter/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/domainhunter/ >/dev/null
git pull -q
pip install -r requirements.txt
python setup.py install
popd >/dev/null

##### Install esedbexport
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}esedbexport${RESET} ~ Tool to extract various credentials and secrets from Windows registry hives"
apt-get -y install git autoconf automake autopoint libtool pkg-config build-essential \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/libyal/libesedb.git /tmp/libesedb/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /tmp/libesedb/ >/dev/null
./synclibs.sh
./autogen.sh
./configure
make
make install
ldconfig
popd >/dev/null

##### Install NTDSXtract
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}NTDSXtract${RESET} ~ Extract information from the Microsoft Active Directory"
apt -y -qq install git \
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
git clone -q -b master https://github.com/scipag/vulscan.git /tmp/vulscan/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /tmp/vulnscan/ >/dev/null
git pull -q
mv *.csv /usr/share/nmap/scripts/
mv *.nse /usr/share/nmap/scripts/
wget -L  -O /usr/share/nmap/scripts/scipvuldb.csv https://www.computec.ch/projekte/vulscan/download/scipvuldb.csv >/dev/null
popd >/dev/null

##### Install Discover
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Discover Tool${RESET}"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/leebaird/discover.git /opt/discover/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/discover/ >/dev/null
git pull -q
popd >/dev/null

##### Install Atom Text Editor
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}NTDSXtract${RESET} ~ Extract information from the Microsoft Active Directory"
apt -y -qq install libgconf-2-4 gconf2 gconf2-common gconf-service gvfs-bin \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
wget -L -O '/tmp/atom.deb' https://atom.io/download/deb  >/dev/null
dpkg -i /tmp/atom.deb

##### Install Bettercap
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Bettercap${RESET}"
apt -y -qq install build-essential ruby-dev libpcap-dev bettercap \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2

##### Install GoPhish
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}GoPhish${RESET}"
wget -L -O '/tmp/gophish.zip' https://github.com/gophish/gophish/releases/download/0.7.1/gophish-v0.7.1-linux-64bit.zip  >/dev/null
unzip /tmp/gophish.zip -d /opt/gophish/

##### Install Responder
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Responder${RESET} ~ MiTM Credential Harvester"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/SpiderLabs/Responder.git /opt/responder/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/responder/ >/dev/null
git pull -q
popd >/dev/null

##### Install Windows Exploit Suggester
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Windows Exploit Suggester${RESET}"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/bitsadmin/wesng.git /opt/wesng/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/wesng/ >/dev/null
git pull -q
python wes.py --update
popd >/dev/null

##### Install ftp client
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}FTP client${RESET}"
apt -y -qq install ftp \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2

##### Install FindFrontableDomains
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}FindFrontableDomains${RESET}"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/rvrsh3ll/FindFrontableDomains.git /opt/FindFrontableDomains/ \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /opt/FindFrontableDomains/ >/dev/null
git pull -q
./setup.sh1 1>&2
popd >/dev/null

##### Update wordlists
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Updating${RESET} wordlists"
apt -y -qq install seclists \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/berzerk0/Probable-Wordlists.git /usr/share/wordlists/Probable-Wordlists \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
pushd /usr/share/wordlist/Probable-Wordlists >/dev/null
git pull -q
popd >/dev/null

##### Update searchsploit
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Updating${RESET} searchsploit"
searchsploit --update

##### Installing Offline Binary Exile Wiki
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Creating${RESET} a clone of BinaryExile Wiki (OFFLINE)"
apt -y -qq install git \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
git clone -q -b master https://github.com/BinaryExile/BinaryExile.github.io /root/BinaryExileWiki \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
gem install bundler 1>&2
pushd /root/BinaryExileWiki >/dev/null
bundle install 1>&2
cat >> /etc/systemd/system/jekyll.service << EOF
[Unit]
Description=Jekyll service
After=syslog.target network.target

[Service]
User=root
Type=simple
WorkingDirectory=/root/BinaryExileWiki/BinaryExile.github.io
ExecStart=/usr/local/bin/bundle exec jekyll serve --watch --source "/root/BinaryExileWiki/BinaryExile.github.io"
ExecStop=/usr/bin/pkill -f jekyll
Restart=always
TimeoutStartSec=60
RestartSec=60
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=jekyll

[Install]
WantedBy=multi-user.target network-online.target
EOF
bundle exec jekyll serve &
popd >/dev/null

##### CLEANUP #####
##### Clean the system
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Cleaning${RESET} the system"
#--- Clean package manager
for FILE in clean autoremove; do apt -y -qq "${FILE}"; done
apt -y -qq purge $(dpkg -l | tail -n +6 | egrep -v '^(h|i)i' | awk '{print $2}')   # Purged packages
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


# close the stderr and stdout file descriptors.
exec 1>&- 2>&-

# Wait for tee to finish since now that other end of the pipe has closed.
wait $TEEPID

echo -e "\n\n ${YELLOW}[i]${RESET} Please reboot the system now to ensure all changes are taken. ${YELLOW}${RESET}"