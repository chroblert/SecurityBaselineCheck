#!/bin/bash
function get_ip_info {
    local ipList=`ifconfig | grep inet |grep -v inet6|grep -v 127|sed 's/^[ ]*//g'|cut -d" " -f2`
    echo $ipList
}
function get_basic_info {
    echo [·] collect basic info
    hostname=`hostname`
    ipList=`get_ip_info`
    kernelVersion=`uname -r`
    if [[ $(cat /proc/version) =~ "Red Hat" ]]; then
        osVersion=`cat /etc/redhat-release|cut -f1,4 -d" "`
    fi
    basic_info={\"hostname\":\"$hostname\",\"ipList\":\"$ipList\",\"kernelVersion\":\"$kernelVersion\",\"osVersion\":\"$osVersion\"}
    echo -e "\033[32m$basic_info \033[0m"
}

function init_check {
    # 1. init configuration
    echo [·] check init configuration
    # 1.1 file system configuration
    # 1.1.1 /tmp separate mount
    mount|grep /tmp |while read res;do
    if [[ -z $res ]]; then
        echo -e "\033[31m[-] /tmp/ not mounted on separate dick\033[0m"
    # 1.1.2 /tmp noexec nosuid
    elif [[ ! $res =~ "noexec" ]];then
        echo -e "\033[31m[-] no noexec option on /tmp partion\033[0m"
        if [[ ! $res =~ "nosuid" ]];then
            echo -e "\033[31m[-] no nosuid option on /tmp partion\033[0m"
        fi
    elif [[ ! $res =~ "nosuid" ]];then
        echo -e "\033[31m[-] no nosuid option on /tmp partion\033[0m"
    fi
    done
    # 1.2 secure boot configuration
    # 1.2.1 /boot/grub2/grub.cfg permission /boot/grub2/user.cfg permission 0600 root:root
    if [[ -f /boot/grub2/grub.cfg ]];then
        res=`stat /boot/grub2/grub.cfg |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4`
        if [[ `echo $res|cut -d"/" -f1` = "0600" ]]; then
            echo -e "\033[32m[+] /boot/grub2/grub.cfg permission is 0600 \033[0m"
        else
            echo -e "\033[31m[-] /boot/grub2/grub.cfg permission is not 0600 \033[0m"
        fi
    fi
    # 1.2.2 Ensure bootloader password is set
    if [[ -f /boot/grub2/grub.cfg ]];then
        res=`grep "^GRUB2 PASSWORD" /boot/grub2/grub.cfg`
        if [[ -n $res ]]; then
            echo -e "\033[32m[+] /boot/grub2/grub.cfg seted password \033[0m"
        else
            echo -e "\033[31m[-] /boot/grub2/grub.cfg not set password \033[0m"
        fi
        
    fi
    # 1.2.3 single user mode need authentication
    if [[ -f /usr/lib/systemd/system/rescue.service ]] && [[ -f /usr/lib/systemd/system/emergency.service ]]; then
        res1=`grep /sbin/sulogin /usr/lib/systemd/system/rescue.service`
        res2=`grep /sbin/sulogin /usr/lib/systemd/system/emergency.service`
        if [[ $res1 = "ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" ]] && [[ $res2 = "ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" ]]; then
            echo -e "\033[32m[+] single user mode need authentication \033[0m"
        else
            echo -e "\033[31m[+] single user mode does not need authentication \033[0m"
        fi
    fi
    # 1.3 Mantary Access Control
    # 1.3.1 ensure the SELinux state is enforcing
    if [[ -f /etc/selinux/config ]]; then
        local num=$(sestatus|grep -c enforcing)
        if [[ $num -gt 1 ]]; then
            echo -e "\033[32m[+] SELinux state is enforcing \033[0m"
        else
            echo -e "\033[31m[-] SELinux state is not enforcing \033[0m"
        fi
    fi
    # 1.3.2 ensure selinux policy is configured
    if [[ -f /etc/selinux/config ]]; then
        res=$(sestatus|grep targeted)
        if [[ -n $res ]]; then
            echo -e "\033[32m[+] SELinux policy is configured \033[0m"
        else
            echo -e "\033[31m[-] SELinux policy is not configure to targeted \033[0m"
        fi

    fi
}
function service_check {
    # 2. service configuration
    echo [·] check service configuration
    # 2.1 time sync
    # 2.1.1 time sync service is installed
    if $(rpm -q ntp 1>/dev/null||rpm -q chrony 1>/dev/null) ; then
        if $(rpm -q ntp 1>/dev/null) ; then
            if [[ -f /etc/ntp.conf ]]; then
                local res=$(egrep "^(server|pool)" /etc/ntp.conf)
                if [[ -n $res ]]; then
                    echo -e "\033[32m[+] remote ntp server is configured \033[0m"
                else
                    echo -e "\033[31m[-] remote ntp server is not configured \033[0m"
                fi
            fi
        fi
        if $(rpm -q chrony 1>/dev/null); then
            if [[ -f /etc/chrony.conf ]]; then
                local res=$(egrep "^(server|pool)" /etc/chrony.conf)
                if [[ -n $res ]]; then
                    echo -e "\033[32m[+] remote chrony server is configured \033[0m"
                else
                    echo -e "\033[31m[-] remote chrony server is not configured \033[0m"
                fi
                
            fi
        fi
    fi        
    # 2.1.2 x-window
    local res=$(rpm -qa xorg-x11*)
    if [[ -z $res ]]; then
        echo -e "\033[32m[+] x11-windows is not installed \033[0m"
    else
        echo -e "\033[31m[-] x11-windows is installed \033[0m"
    fi
}
function network_check {
    # 3. network configuration
    echo [·] check network configuration
    # 3.1 hosts file configuration
    # 3.1.1 check /etc/hosts.deny file
    if [[ -f /etc/hosts.deny ]]; then
        echo -e "\033[32m[+] file /etc/hosts.deny exists \033[0m"
        local res=`stat /etc/hosts.deny |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4`
        if [[ $(echo $res|cut -d"/" -f1) = "0644" ]];then
            echo -e "\033[32m[+] file /etc/hosts.deny permission is 0644 \033[0m"
        else
            echo -e "\033[31m[-] file /etc/hosts.deny permission is not 0644 \033[0m"
        fi

        local res=$(egrep "^[^#].+" /etc/hosts.deny)
        if [[ -n $res ]]; then
            echo -e "\033[32m[+] file /etc/hosts.deny is configured \033[0m"
        else
            echo -e "\033[31m[-] file /etc/hosts.deny is not configured \033[0m"
        fi
    else
        echo -e "\033[31m[-] file /etc/hosts.deny does not exists \033[0m"
    fi
    # 3.1.2 check /etc/hosts.allow file
    if [[ -f /etc/hosts.allow ]]; then
        echo -e "\033[32m[+] file /etc/hosts.allow exists \033[0m"
        local res=`stat /etc/hosts.allow |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4`
        if [[ $(echo $res|cut -d"/" -f1) = "0644" ]];then
            echo -e "\033[32m[+] file /etc/hosts.allow permission is 0644 \033[0m"
        else
            echo -e "\033[31m[-] file /etc/hosts.allow permission is not 0644 \033[0m"
        fi

        local res=$(egrep "^[^#].+" /etc/hosts.deny)
        if [[ -n $res ]]; then
            echo -e "\033[32m[+] file /etc/hosts.allow is configured \033[0m"
        else
            echo -e "\033[31m[-] file /etc/hosts.allow is not configured \033[0m"
        fi
    else
        echo -e "\033[31m[-] file /etc/hosts.allow does not exists \033[0m"
    fi

    # 3.2 firewall configuration
    # 3.2.1 ensure iptables is installed
    if $(rpm -q iptables 1>/dev/null); then
        echo -e "\033[32m[+] iptables is installed \033[0m"
        # 3.2.2 ensure INPUT OUTPUT chain policy is DROP
        iptables -L|grep policy|while read x;do
            if [[ $x =~ "INPUT" ]] && [[ $x =~ "DROP" ]]; then
                echo -e "\033[32m[+] INPUT chain policy is DROP \033[0m"
            elif [[ $x =~ "INPUT" ]] && [[ ! $x =~ "DROP" ]]; then
                echo -e "\033[31m[-] INPUT chain policy is not DROP \033[0m"
            fi
            if [[ $x =~ "OUTPUT" ]] && [[ $x =~ "DROP" ]]; then
                echo -e "\033[32m[+] OUTPUT chain policy is DROP \033[0m"
            elif [[ $x =~ "OUTPUT" ]] && [[ ! $x =~ "DROP" ]]; then
                echo -e "\033[31m[-] OUTPUT chain policy is not DROP \033[0m"
            fi
        done
    else
        echo -e "\033[31m[-] iptables is not installed \033[0m"
    fi
}

function auditd_check {
	# 4. auditd configuration
	echo [·] check auditd configuration
	# 4.1 ensure auditd is enabled
    echo "-[·] check auditd if is enabled"
	if [[ $(systemctl is-enabled auditd) = "enabled" ]]; then
		echo -e "\033[32m-[+] auditd is enabled \033[0m"
	else
		echo -e "\033[31m-[-] auditd is not enabled \033[0m"
	fi
	# 4.2 some settings in /etc/audit/auditd.conf
    echo "-[·] settings in /etc/audit/auditd.conf"	
    if [[ -f /etc/audit/auditd.conf ]]; then
        maxLogFile=$(grep "^max_log_file[[:blank:]]=" /etc/audit/auditd.conf|sed "s/ //g"|cut -d"=" -f 2)
        maxLogFileAction=$(grep "^max_log_file_action" /etc/audit/auditd.conf|sed "s/ //g"|cut -d"=" -f 2)
        spaceLeftAction=$(grep "^space_left_action" /etc/audit/auditd.conf|sed "s/ //g"|cut -d"=" -f 2)
        numLogs=$(grep "^num_logs" /etc/audit/auditd.conf|sed "s/ //g"|cut -d"=" -f 2)
        if [[ -n $maxLogFile ]]; then
            echo -e "\033[32m-[+] max_log_file size is ${maxLogFile} M \033[0m"
        else
            echo -e "\033[31m-[-] max_log_file size is not setted \033[0m"
        fi
        if [[ -n $maxLogFileAction ]]; then
            echo -e "\033[32m-[+] max_log_file_action is ${maxLogFileAction}\033[0m"
        else
            echo -e "\033[31m-[-] max_log_file_action is not setted \033[0m"
        fi
        if [[ -n $spaceLeftAction ]]; then
            echo -e "\033[32m-[+] space_left_action is ${spaceLeftAction}\033[0m"
        else
            echo -e "\033[31m-[-] space_left_action is not setted \033[0m"
        fi
        if [[ -n $numLogs ]]; then
            echo -e "\033[32m-[+] the num of logs is ${numLogs} \033[0m"
        else
            echo -e "\033[31m-[-] num_logs is not setted \033[0m"
        fi
    fi
    # 4.3 rules in /etc/audit/audit.rules
    # arch 64
    echo "-[·] time-change" 
    if [[ -f /etc/audit/audit.rules ]]; then
        echo -e "\033[32m-[+] /etc/audit/audit.rules is exist \033[0m"
        # 4.3.1 time-change
        if [[ -n $(grep time /etc/audit/audit.rules) ]]; then
            local timeChangeList=$(egrep "(stime|clock_settime|adjtimex|settimeofday|/etc/localtime)" /etc/audit/audit.rules|wc -l)
            if [[ ${timeChangeList} -gt 3 ]]; then
                echo -e "\033[32m-[+] audith the change of date and time \033[0m"
            elif [[ ${timeChangeList} -gt 1 ]]; then
                echo -e "\033[31m-[-] not fully set rule about audit the change of date and time \033[0m"
            else 
                echo -e "\033[31m-[-] not set rule about audit the change of date and time \033[0m"
            fi
        else
            echo -e "\033[31m-[-] not set rule about audit the change of date and time \033[0m"
        fi
        # 4.3.2 user and group change
        echo "-[·] user and group change"
        local keyArray=("/etc/passwd" "/etc/group" "/etc/gshadow" "/etc/shadow" "/etc/security/opasswd")
        for i in ${keyArray[@]} ; do
            if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                echo -e "\033[32m-[+] audit the change of $i \033[0m"
            else
                echo -e "\033[31m-[-] not audit the change of $i \033[0m"
            fi
        done
        # 4.3.3 system's network environment change
        echo "-[·] system's network environment change"
        local keyArray=("/etc/issue" "/etc/issue.net" "/etc/hosts" "/etc/sysconfig/network" "/etc/sysconfig/network-scripts/" )
        for i in ${keyArray[@]} ; do
                if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                echo -e "\033[32m-[+] audit the change of $i \033[0m"
            else
                echo -e "\033[31m-[-] not audit the change of $i \033[0m"
            fi
        done
        local keyArray=("sethostname" "setdomainname")
        for i in ${keyArray[@]} ; do
                if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                echo -e "\033[32m-[+] audit the use of syscall  $i \033[0m"
            else
                echo -e "\033[31m-[-] not audit the use of syscall $i \033[0m"
            fi
        done
        # 4.3.4 system's Mandatory Access Controls change
        echo "-[·] system's Mandatory Access Controls change"
        local keyArray=("/etc/selinux" "/usr/share/selinux")
        for i in ${keyArray[@]} ; do
                if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                echo -e "\033[32m-[+] audit the change of   $i \033[0m"
            else
                echo -e "\033[31m-[-] not audit the change of $i \033[0m"
            fi
        done
        # 4.3.5 audit events of login and logout
        echo "-[·] audit events of login and logout"
        local keyArray=("/var/log/lastlog" "/var/run/faillock/")
        for i in ${keyArray[@]} ; do
                if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                echo -e "\033[32m-[+] audit the change of   $i \033[0m"
            else
                echo -e "\033[31m-[-] not audit the change of $i \033[0m"
            fi
        done
        # 4.3.6 audit the change of discretionary access control
        echo "-[·] audit the change of discretionary access control"
        local keyArray=("(chmod|fchmod|fchmodat)" "(chown|fchown|fchownat)" "(setxattr|lsetxattr|removexattr)" "(lock|time)")
        for i in ${keyArray[@]} ; do
            if [[ -n $(egrep $i /etc/audit/audit.rules) ]]; then
                i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g')
                echo -e "\033[32m-[+] audit the use of systemcall  $i \033[0m"
            else
                i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g')
                echo -e "\033[31m-[-] not audit the use of systemcall $i \033[0m"
            fi
        done
        # 4.3.7 audit the events of unsuccessful unauthorized file access attempts
        echo "-[·] audit the events of unsuccessful unauthorized file access attempts"
        local keyArray=("(create|open|openat|truncate|ftruncate).*?exit=-EACCESS" "(create|open|openat|truncate|ftruncate).*?exit=-EPERM" )
        for i in ${keyArray[@]} ; do
            if [[ -n $(egrep $i /etc/audit/audit.rules) ]]; then
                i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                echo -e "\033[32m-[+] audit the use of systemcall  $i \033[0m"
            else
                i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                echo -e "\033[31m-[-] not audit the use of systemcall $i \033[0m"
            fi
        done
        # 4.3.8 audit the use of privileged commands
        echo "-[·] audit the use of privileged commands"
        #find / -name "passwd"
        local res=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f) #|awk '{print "-a always,exit -F path="$1"-F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"}'
        for i in ${res[@]} ; do
            if [[ -n $(egrep $i /etc/audit/audit.rules) ]]; then
                i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                echo -e "\033[32m-[+] audit the use of command  $i \033[0m"
            else
                i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                echo -e "\033[31m-[-] not audit the use of command $i \033[0m"
            fi
        done
        # 4.3.9 audit the change of file sudoer
        echo "-[·] audit the change of file sudoer"
        local keyArray=("/etc/sudoers" "/etc/sudoers.d/")
        for i in ${keyArray[@]} ; do
            if [[ -n $(egrep $i /etc/audit/audit.rules) ]]; then
                i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                echo -e "\033[32m-[+] audit the change of file  $i \033[0m"
            else
                i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                echo -e "\033[31m-[-] not audit the change of file $i \033[0m"
            fi
        done
        # 4.3.10 check the audit configuration is setted to immutable unless reboot the server
        echo "-[·] check the audit configuration is setted to immutable unless reboot the server"
        local res=$(grep "^\s*[^#]" /etc/audit/audit.rules|tail -1|egrep "-e.*?2")
        if [[ -n $res ]]; then
            echo -e "\033[32m-[+] auditd setted -e 2 \033[0m"
        else
            echo -e "\033[31m-[-] auditd not setted -e 2 \033[0m"
        fi
    else
        echo -e "\033[32m[+] /etc/audit/audit.rules is not exist \033[0m"
    fi
}

function log_check {
    echo "[·] check log configuration"
	# 5.1 ensure auditd is enabled
    echo "-[·] check rsyslog if is enabled"
	if [[ $(systemctl is-enabled rsyslog) = "enabled" ]]; then
		echo -e "\033[32m-[+] rsyslog is enabled \033[0m"
	else
		echo -e "\033[31m-[-] rsyslog is not enabled \033[0m"
	fi
    

}

function authentication_check {
    echo "[·] check cron ssh pam and env configuration"
    # 6.1 cron configuration
    echo "-[·] check cron configuration"
    # 6.1.1 check cron service is enabled
    echo "-[·] check crond if is enabled"
	if [[ $(systemctl is-enabled crond) = "enabled" ]]; then
		echo -e "\033[32m-[+] crond is enabled \033[0m"
	else
		echo -e "\033[31m-[-] crond is not enabled \033[0m"
	fi
    # 6.1.2 check cron's configuration file permission
    echo "-[·] check cron's configuration file permission"
    local keyArray=("/etc/crontab" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d")
    for i in ${keyArray[@]} ; do
        local res=$(stat $i |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4|cut -d"/" -f1)
        if [[ $res = "0600" ]] || [[ $res = "0700" ]]; then
            echo -e "\033[32m-[+] file $i's permission is $res \033[0m"
        else
            echo -e "\033[31m-[-] file $i's permission is $res ,not 0600 or 0700 \033[0m"
        fi
    done
    # 6.1.3 check cron.allow cron.deny permission and owner
    echo "-[·] check cron.allow cron.deny configuration file permission"
    local keyArray=("/etc/cron.allow" "/etc/cron.deny")
    for i in ${keyArray[@]} ; do
        if [[ ! -f $i ]]; then
            echo -e "\033[31m-[-] file $i not exist \033[0m"
            continue
        fi
        local res1=$(stat $i |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4|cut -d"/" -f1)
        local res2=$(stat $i |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f3,4|sed 's/)//g'|cut -d" " -f3,6)
        if [[ $res1 = "0600" ]] || [[ $res1 = "0700" ]]; then
            echo -e "\033[32m-[+] file $i's permission is $res \033[0m"
        else
            echo -e "\033[31m-[-] file $i's permission is $res ,not 0600 or 0700 \033[0m"
        fi
        if [[ $res2 = "root root" ]]; then
            echo -e "\033[32m-[+] file $i's owner is $res2 \033[0m"
        else
            echo -e "\033[31m-[-] file $i's owner is not root \033[0m"
        fi
    done
    
    # 6.2 SSH configuration
    echo "-[·] check ssh configuration"
	if [[ $(systemctl is-enabled sshd) = "enabled" ]]; then
        # 6.2.1 /etc/ssh/sshd_config permission 0600
        local file="/etc/ssh/sshd_config"
        local res=$(stat $file |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4|cut -d"/" -f1)
        if [[ $res = "0600" ]]; then
            echo -e "\033[32m-[+] file $file's access permission is $res \033[0m"
        else
            echo -e "\033[3-m-[-] file $file's access permission is $res \033[0m"
        fi
        # 6.2.2 check ssh x11 forwarding if is disabled
        local res=$(grep "^X11Forwaring" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            echo -e "\033[32m-[+] X11Forwarding no \033[0m"
        else
            echo -e "\033[31m-[-] not set X11Forwarding no \033[0m"
        fi
        # 6.2.3 check ssh MaxAUTHTries if is 4
        local res=$(grep "^MaxAuthTries" /etc/ssh/sshd_config)
        if [[ -n $res ]]; then
            echo -e "\033[32m-[+] $res \033[0m"
        else
            echo -e "\033[31m-[-] not set MaxAuthTries \033[0m"
        fi
        # 6.2.4 check ssh IgnoreRhosts if is enabled
        local res=$(grep "^IgnoreRhosts" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep yes) ]]; then
            echo -e "\033[32m-[+] IgnoreRhosts yes \033[0m"
        else
            echo -e "\033[31m-[-] not set IgnoreRhosts no\033[0m"
        fi
        # 6.2.5 check ssh HostbasedAuthentication if is disabled
        local res=$(grep "^HostbasedAuthentication" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            echo -e "\033[32m-[+] HostbasedAuthentication no \033[0m"
        else
            echo -e "\033[31m-[-] not set HostbasedAuthentication no\033[0m"
        fi
        # 6.2.6 check ssh root login if is diabled
        local res=$(grep "^PermitRootLogin" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            echo -e "\033[32m-[+] PermitRootLogin no \033[0m"
        else
            echo -e "\033[31m-[-] not set PermitRootLogin no\033[0m"
        fi
        # 6.2.7 check ssh PermitEmptyPasswords if is diabled
        local res=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            echo -e "\033[32m-[+] PermitEmptyPasswords no \033[0m"
        else
            echo -e "\033[31m-[-] not set PermitEmptyPasswords no\033[0m"
        fi
        # 6.2.8 check ssh PermitUserEnvironment if is diabled
        local res=$(grep "^PermitUserEnvironment" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            echo -e "\033[32m-[+] PermitUserEnvironment no \033[0m"
        else
            echo -e "\033[31m-[-] not set PermitUserEnvironment no\033[0m"
        fi
        # 6.2.9 check if set specific MAC algorithms
        local res=$(grep "^MACs" /etc/ssh/sshd_config)
        if [[ -n $res ]]; then
            echo -e "\033[32m-[+] will use specific MAC algorithms $res \033[0m"
        else
            echo -e "\033[31m-[-] not set specific MAC algorithms\033[0m"
        fi
        # 6.2.10 check SSH idle Timeout Interval if is configured
        local res=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config)
        if [[ -n $res ]]; then
            echo -e "\033[32m-[+] $res \033[0m"
        else
            echo -e "\033[31m-[-] not set ClientAliveInterval \033[0m"
        fi
        # 6.2.11 check SSH LoginGrace Time
        local res=$(grep "^LoginGraceTime" /etc/ssh/sshd_config)
        if [[ -n $res ]]; then
            echo -e "\033[32m-[+] $res \033[0m"
        else
            echo -e "\033[31m-[-] not set LoginGraceTime \033[0m"
        fi
	else
		echo -e "\033[32m-[+] sshd is not enabled \033[0m"
	fi

    # 6.3 PAM configuration
    echo "-[·] check pam configuration"
    # 6.3.1 password creation policy
    if [[ -f /etc/security/pwquality.conf ]]; then
        local minlen=$(grep ^minlen /etc/security/pwquality.conf | sed 's/ //g')
        local minclass=$(grep ^minclass /etc/security/pwquality.conf |sed 's/ //g')
        if [[ -n $minlen ]]; then
            echo -e "\033[32m-[+] minimime length of password is $(echo $minlen|cut -d= -f2) \033[0m"
        else
            echo -e "\033[31m-[-] not set minlen \033[0m"
        fi
        if [[ -n $minclass ]]; then
            echo -e "\033[32m-[+] minclass of password is $(echo $minclass|cut -d= -f2) \033[0m"
        else
            local keyArray=("^dcredit" "^lcredit" "^ocredit" "^ucredit")
            local tmpCount=0
            for i in ${keyArray[@]}; do
                if [[ -n  $(grep $i /etc/security/pwquality.conf) ]]; then
                    tmpCount=$(expr 1 + $tmpCount)
                fi
            done
            if [[ tmpCount -ge 2 ]]; then
                echo -e "\033[32m-[+] minclass of passwd is $tmpCount \033[0m"
            else
                echo -e "\033[31m-[-] not set minclass \033[0m"
            fi
        fi
    fi
    # 6.3.2 lock account and unlock time
    local files=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth")
    local keyArray=("pam_faillock\.so.*?unlock_time")
    for i in ${files[@]}; do
        for k in ${keyArray[@]}; do
            if [[ -n $(egrep $k $i ) ]]; then
                echo -e "\033[32m-[+] set lock and unlock_time in $i \033[0m"
            else
                echo -e "\033[31m-[-] not set lock and unlock_time in $i \033[0m"
            fi
        done
    done
    # 6.3.3 check password reuse if is limited
    for i in ${files[@]}; do
        local res=$(egrep '^password\s+sufficient\s+pam_unix.so' $i)
        if [[ -n $res ]] && [[ $res =~ "remember=" ]]; then
            local tmp=$(echo $res|sed 's/.*\(remember=[[:digit:]]\).*/\1/g'|sed 's/ //g'|cut -d= -f2)
            echo -e "\033[32m-[+] password reuse limit is $tmp in $i \033[0m"
        else
            echo -e "\033[31m-[-] passowrd reuse limit not set in $i \033[0m"
        fi
    done
    # 6.3.4 check the algorithm of store password if is sha512
    for i in ${files[@]}; do
        local res=$(egrep '^password\s+sufficient\s+pam_unix.so' $i)
        if [[ -n $res ]] && [[ $res =~ "sha512" ]]; then
            echo -e "\033[32m-[+] password storage algorithm is set to sha512 in $i \033[0m"
        else
            echo -e "\033[31m-[-] password storage algorithm is not specific to sha512 in $i \033[0m"
        fi
    done
    # 6.4 user accounts and environment
    echo "-[·] check user accounts and environment"
    if [[ -f /etc/login.defs ]]; then
        # 6.4.1 basic settings
        local file='/etc/login.defs'
        passMaxDays=$(grep ^PASS_MAX_DAYS $file|sed -r 's/[^1234567890]*([1234567890]{1,})/\1/g')
        passMinDays=$(grep ^PASS_MIN_DAYS $file|sed -r 's/[^1234567890]*([1234567890]{1,})/\1/g')
        passWarnAge=$(grep ^PASS_WARN_DAYS $file|sed -r 's/[^1234567890]*([1234567890]{1,})/\1/g')
        inactive=$(useradd -D|grep INACTIVE|sed 's/ //g'|cut -d= -f2)
        if [[ $passMaxDays -le 90 ]]; then
            echo -e "\033[32m-[+] the maximume days of password have to change is $passMaxDays \033[0m"
        else
            echo -e "\033[31m-[-] the maximume days of password have to change is $passMaxDays ,should less than 90 day\033[0m"
        fi
        if [[ $passMinDays -ge 7 ]]; then
            echo -e "\033[32m-[+] the minimume days of password have to change is $passMinDays \033[0m"
        else
            echo -e "\033[31m-[-] the minimume days of password have to change is $passMinDays ,should great than 7 day\033[0m"
        fi
        if [[ $passWarnAge -ge 7 ]]; then
            echo -e "\033[32m-[+] the minimume days of warn password need to change is $passWarnAge \033[0m"
        else
            echo -e "\033[31m-[-] the minimume days of warn password need to change is $passWarnAge ,should greate than 7 day\033[0m"
        fi
        if [[ $inactive != -1 ]]; then
            echo -e "\033[32m-[+] auto lock account when the  $inactive day haven't login \033[0m"
        else
            echo -e "\033[31m-[-] haven't set day of auto lock accounts \033[0m"
        fi
        # 6.4.2 check system's account if is unlogin
        local res=$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}')
        if [[ -z $res ]]; then
            echo -e "\033[32m-[+] system account can't login \033[0m"
        else
            echo -e "\033[31m-[-] the below user's shell need set to /sbin/nologin \033[0m"
        fi
        # 6.4.3 check default group for the root account if is GID 0
        local res=$(grep "^root:" /etc/passwd|cut -d: -f4)
        if [[ $res = 0 ]]; then
            echo -e "\033[32m-[+] default group for the root account is GID 0 \033[0m"
        else
            echo -e "\033[31m-[-]] default group for the root account is is GID $res,not GID 0 \033[0m"
        fi
        # 6.4.4 check default user shell timeout if is 900 seconds or less
        local files=("/etc/bashrc" "/etc/profile")
        for file in ${files[@]}; do
            if [[ ! -f $file ]]; then
                continue
            fi
            local res=$(grep "^TMOUT" $file|sed 's/ //g'|cut -d= -f2)
            if [[ -z $res ]]; then
                echo -e "\033[31m-[-] not set TMOUT in file $file \033[0m"
                continue
            fi
            if [[ $res -le 900 ]]; then
                echo -e "\033[32m-[+] when idle time great then $res seconds will close connection \033[0m"
            else
                echo -e "\033[31m-[-] when idle time great then $res seconds will close connection,the time should less than 900 seconds \033[0m"
            fi
        done
        # 6.4.5 check access to su command if is restricted
        local res=$(grep pam_wheel.so /etc/pam.d/su)
        if [[ -n $res ]]; then
            local res=$(grep wheel /etc/group|cut -d: -f4)
            if [[ -n $res ]]; then
                echo -e "\033[32m-[+] access to su command is specific to $res \033[0m"
            else
                echo -e "\033[31m-[-] access to su command is not restricted \033[0m"
            fi
        else
            echo -e "\033[31m-[-] access to su command is not restricted \033[0m"
        fi
    else
        echo -e "\033[31m-[-] file /etc/login.defs is not exist \033[0m"
    fi
}

function system_check {
    echo "[·] check permission of important file and configuration of user and group"
    # 7.1 check permission of important file and uid gid
    echo "-[·] check permission of important file"
    local files=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow" "/etc/passwd-" "/etc/shadow-" "/etc/group-" "/etc/gshadow-")
    for file in ${files[@]}; do
        local perm=$(stat $file |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4|cut -d"/" -f1)
        local uidGid=$(stat /etc/passwd |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f3,4|sed 's/ //g'|sed -r 's/([[:digit:]]{1,}).*([[:digit:]]{1,}).*/\1 \2/g'|cut -d" " -f1,2)
        if [[ $file =~ "shadow" ]]; then
            if [[ $perm = "0000" ]]; then
                echo -e "\033[32m-[+] file $file's permission is $perm \033[0m"
            else
                echo -e "\033[31m-[-] file $file's permission is $perm,should set to 0000 \033[0m"
            fi
        else
            if [[ $perm = "0644" ]]; then
                echo -e "\033[32m-[+] file $file's permission is $perm \033[0m"
            else
                echo -e "\033[31m-[-] file $file's permission is $perm,should set to 0644 \033[0m"

            fi
        fi
        if [[ $uidGid = "0 0" ]]; then
            echo -e "\033[32m-[+] file $file's uid gid is $uidGid \033[0m"
        else
            echo -e "\033[31m-[-] file $file's uid gid is $uidGid,should set to 0 0 \033[0m"
        fi
    done
    # 7.2 check configuration of user and group
    echo "-[·] check configuration of user and group"
    # 7.2.1 check if user's password is empty
    users=$(cat /etc/shadow |awk -F: '($2=="!!"){print $1}'|while read x;do 
        res=$(grep ${x} /etc/passwd|cut -d: -f7); if [[ $res != "/sbin/nologin" ]] && [[ $res != "/sbin/shutdon" ]] && [[ $res != "/sbin/halt" ]]; then 
            echo $x
            #echo -e "\033[31m-[-] $x should have a passwd,not empty \033[0m"; 
            fi;
        done)
    if [[ -z $users ]]; then
        echo -e "\033[32m-[+] all user account have set password \033[0m"
    else
        echo -e "\033[31m-[-] user:$(echo $users|sed 's/\n/ /g') should set a password ,rather than empty \033[0m"
    fi
    # 7.2.2 check if root is the only UID 0 account
    local users=$(cat /etc/passwd|awk -F: '($3==0){print $1}')
    if [[ $users = 'root' ]]; then
        echo -e "\033[32m-[+] root is the only account that uid is 0 \033[0m"
    else
        echo -e "\033[31m-[-] $(echo $users|sed 's/root//g') uid should not be 0 \033[0m"
    fi
    # 7.2.3 check root PATH integrith
    if [ "$(echo $PATH|grep ::)" != "" ]; then
        echo -e "\033[31m-[-] Empty Directory in PATH (::) \033[0m"
    fi
    if [ "$(echo $PATH|grep :$)" != "" ]; then
        echo -e "\033[31m-[-] Trailing : in PATH \033[0m"
    fi
    path=$( echo $PATH|sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g')
    set -- $path
    while [[ $1 != "" ]]; do
        if [[ $1 = "." ]]; then
            echo -e "\033[31m-[-] PATH contains . \033[0m"
            shift
            continue
        fi
        if [[ -d $1 ]]; then
            local dirperm=$(ls -ldH $1|cut -d" " -f1)
            if [[ $(echo $dirperm|cut -c6) != "-" ]]; then
                echo -e "\033[31m-[-] Group Write permission should not set on directory $1 \033[0m"
            fi
            if [[ $(echo $dirperm|cut -c9) != "-" ]]; then
                echo -e "\033[31m-[-] Other Write permission should not set on directory $1 \033[0m"
            fi
            local dirown=$(ls -ldH $1|awk '{print $3}')
            if [[ $dirown != "root" ]]; then
                echo -e "\033[31m-[-] dir $1's owner is $dirown,should be root \033[0m"
            fi
        else
            echo -e "\033[31m-[-] $1 is not a directory or not exist \033[0m"
        fi
        shift
    done
    # 7.2.4 check if is all users' home directories exist
    cat /etc/passwd|egrep -v '^(root|halt|sync|shutdown)'|awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false"){print $1 " " $6}'|while read user dir; do
        if [[ ! -d $dir ]]; then
            echo -e "\033[31m-[-] the home directory ($dir) of user $user does not exist \033[0m"
        else
            # 7.2.5 check if users' home directories permissions are 750 or more restrictive
            local dirperm=$(ls -ld $dir|cut -d" " -f1)
            if [[ $(echo $dirperm |cut -c6) != "-" ]]; then
                echo -e "\033[31m-[-] Group Write permission set on the home directory ($dir) of user $user \033[0m"
            fi
            if [[ $(echo $dirperm |cut -c8) != "-" ]]; then
                echo -e "\033[31m-[-] Other Read permission set on the home directory ($dir) of user $user \033[0m"
            fi
            if [[ $(echo $dirperm |cut -c9) != "-" ]]; then
                echo -e "\033[31m-[-] Other Write permission set on the home directory ($dir) of user $user \033[0m"
            fi
            if [[ $(echo $dirperm |cut -c10) != "-" ]]; then
                echo -e "\033[31m-[-] Other Execute permission set on the home directory ($dir) of user $user \033[0m"
            fi
            # 7.2.6 check if is users own their home directory
            local owner=$(stat -L -c "%U" $dir)
            if [[ $owner != $user ]]; then
                echo -e "\033[31m-[-]The home directory ($dir) of user $user is owned by $owner \033[0m"
            fi
            # 7.2.7 check users' dot files are not group or world  writable
            for file in $dir/.[A-Za-z0-9]*; do
                if [[ ! -h $file ]] && [[ -f $file ]]; then
                    local fileperm=$(ls -ld $file|cut -d" " -f1)
                    if [[ $(echo $fileperm|cut -c6) != "-" ]]; then
                        echo -e "\033[31m-[-] Group Write permission set on file $file \033[0m"
                    fi
                    if [[ $(echo $fileperm|cut -c9) != "-" ]]; then
                        echo -e "\033[31m-[-] Other Write permission set on file $file \033[0m"
                    fi
                fi
            done
            # 7.2.8 check if no usrs have .netrc .rhosts .forward file
            if [[ ! -h $dir/.netrc ]] && [[ -f $dir/.netrc ]]; then
                echo -e "\033[31m-[-] .netrc file $dir/.netrc exists \033[0m"
            fi
            if [[ ! -h $dir/.rhosts ]] && [[ -f $dir/.rhosts ]]; then
                echo -e "\033[31m-[-] .rhosts file $dir/.rhosts exists \033[0m"
            fi
            if [[ ! -h $dir/.forward ]] && [[ -f $dir/.forward ]]; then
                echo -e "\033[31m-[-] .forward file $dir/.forward exists \033[0m"
            fi
        fi
        # 7.2.9 check if all groups in /etc/passwd exist in /etc/group
        for i in $(cut -d: -s -f4 /etc/passwd|sort -u); do
            grep -q -P "^.*?:[^:]*:$i" /etc/group
            if [[ $? -ne 0 ]]; then
                echo -e "\033[31m-[-] Group $i is referenced by /etc/passwd but does not exist in /etc/group \033[0m"
            fi
        done
    done
    # 7.2.10 check if every user has a unique UID
    cat /etc/passwd|cut -d":" -f3|sort -n|uniq -c|while read x; do
        [[ -z $x ]] && break
        set - $x
        if [[ $1 -gt 1 ]]; then
            local users=$(awk -F: '($3==n){print $1}' n=$2 /etc/passwd|xargs)
            echo -e "\033[31m-[-] Duplicate UID $2 : $users \033[0m"
        fi
    done
    # 7.2.11 check if every group has a unique GID
    cat /etc/group|cut -d":" -f3|sort -n|uniq -c|while read x; do
        [[ -z $x ]] && break
        set - $x
        if [[ $1 -gt 1 ]]; then
            local groups=$(awk -F: '($3==n){print $1}' n=$2 /etc/group|xargs)
            echo -e "\033[31m-[-] Duplicate GID $2 : $groups \033[0m"
        fi
    done
    # 7.2.12 check if user name is unique
    cat /etc/passwd|cut -d":" -f1|sort -n|uniq -c|while read x; do
        [[ -z $x ]] && break
        set - $x11
        if [[ $1 -gt 1 ]]; then
            local uids=$(awk -F: '($1 == n){print $3}' n=$2 /etc/passwd|xargs)
            echo -e "\033[31m-[-] Duplicate user name $2 : $uids \033[0m"
        fi
        done
    # 7.2.13 check if group name is unique
    cat /etc/group|cut -d":" -f1|sort -n|uniq -c|while read x; do
        [[ -z $x ]] && break
        set - $x11
        if [[ $1 -gt 1 ]]; then
            local gids=$(awk -F: '($1 == n){print $3}' n=$2 /etc/group|xargs)
            echo -e "\033[31m-[-] Duplicate group name $2 : $gids \033[0m"
        fi
        done
    

}

echo """
==================================
|        Linux 基线检查工具      |
|        author:JC0o0l           |
|        version:1.0             |
==================================
"""
#get_basic_info
#init_check
#service_check
#network_check
#auditd_check
#log_check
#authentication_check
system_check