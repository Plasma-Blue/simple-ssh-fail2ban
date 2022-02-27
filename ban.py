from collections import Counter
import time
import os

def _getSuspiciousIPs(secureLogPth, times):
    '''analysis secure log and find ips to ban'''
    with open(secureLogPth, 'r') as f:
        lines = f.readlines()
    suspiciousIPs = [line.split(' ')[-4] for line in lines if 'Failed password for' in line]
    d = Counter(suspiciousIPs)
    banIPs = [ip for ip in d if d[ip] >= times]
    return set(banIPs)

def _analysisBanedIP(sshdLogPth):
    '''analysis sshd config and find ips banned'''
    with open(sshdLogPth, 'r') as f:
        lines = f.readlines()
    banedIPs = [line.split('@')[-1].strip('\n') for line in lines if 'DenyUsers' in line]
    return set(banedIPs)

def getBanIPs(secureLogPth, sshdConfigPth, times):
    suspiciousIPs = _getSuspiciousIPs(secureLogPth, times)
    banedIPs = _analysisBanedIP(sshdConfigPth)
    banIPs = suspiciousIPs - banedIPs
    return banIPs

def write2Config(secureLogPth='/var/log/secure', sshdConfigPth='/etc/ssh/sshd_config', times=3):
    assert os.path.exists(secureLogPth) and os.path.exists(sshdConfigPth)
    banIPs = getBanIPs(secureLogPth, sshdConfigPth, times)
    print(f"Baned IP: {banIPs}")
    write2SSHD(banIPs)
    write2FirewallD(banIPs)

def write2SSHD(banIPs):
    l = [f'DenyUsers *@{ip}\n' for ip in banIPs]
    if len(l) != 0:
        l.insert(0, f'\n# {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}\n')
    with open(sshdConfigPth, 'a+') as f:
        f.writelines(l)
    ls = [i.strip('\n') for i in l]

def write2FirewallD(banIPs):
    for ip in banIPs:
        os.system(
        f"""
            firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="{ip}" reject'
        """)
    os.system('firewall-cmd --reload')
    os.system('systemctl restart firewalld.service')

if '__name__' == '__main__':
    times = 1 # Patience is limited.
    secureLogPth = '/var/log/secure'
    sshdConfigPth = '/etc/ssh/sshd_config'
    write2Config(secureLogPth, sshdConfigPth, times)
