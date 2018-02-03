from netrecon import settings
from pexpect import spawnu, TIMEOUT, EOF


# ----------------
# pexpect SSH info
# ----------------
SSH_NEW_KEY = '.Are you sure you want to continue connecting (yes/no)?'
SSH_BAD_KEY = 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!'
SSH_REFUSED = 'Connection refused'
SSH_OUTDATED_KEX = '.no matching key exchange method found'
SSH_OUTDATED_CIPHER = '.no matching cipher found. Their offer: aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc'
SSH_OUTDATED_PROTOCOL = 'Protocol major versions differ: 2 vs. 1\\r\\r\\n'
PASSWORD = '[P|p]assword'
PASSWORD_W_S = '[P|p]assword '
PERMISSION_DENIED = 'Permission denied, please try again.'

# -----------
# ssh prompts
# -----------
GT_PROMPT = '>$'
HASH_PROMPT = '#$'
GT_PROMPT_W_S = '> $'
HASH_PROMPT_W_S = '# $'

# ----------------------
# Cisco generic commands
# ----------------------
SHOWVER = 'show version'
SHOW_OS = 'show version | include Software'
ENABLE = 'enable'

# ------------------
# Cisco IOS commands
# ------------------
IOS_TERMLEN0 = 'terminal length 0'
IOS_SHOW_CDP_DETAIL = 'show cdp neighbors detail'
IOS_SHOW_ADJACENCY = 'show adjacency'
IOS_SHOW_LOCAL_CONNECTIONS = 'show ip route connected | in C'
IOS_SHOW_ARP = 'show arp | exclude Incomplete'
IOS_SHOWIPINTBR = 'show ip int br | exclude unassigned'
IOS_SHOW_CAM = 'show mac address-table | exclude All'
IOS_SWITCH_SHOW_MODEL = 'show version | include Model number'
IOS_RTR_SHOW_MODEL = 'show version | include \*'
IOS_SWITCH_SHOW_SERIALNUM = 'show version | include System serial number'
IOS_RTR_SHOW_SERIALNUM = 'show version | include Processor board ID'
IOS_SHOW_LICS = 'show version | include License Level'
IOS_LAST_RESORT_SHOW_MODEL = 'show version  | include (WS)'

# ------------------
# Cisco ASA commands
# ------------------
ASA_TERMPAGER0 = 'terminal pager 0'
ASA_SHOWARP = 'show arp'
ASA_SHOW_LOCAL_CONNECTIONS = 'show route | in C'
ASA_SHOW_XLATE = 'show xlate'
ASA_SHOW_CONN = 'show conn'
ASA_SHOW_SERIALNUM = 'show version | include Serial Number:'
ASA_SHOW_MODEL = 'show version | include Hardware:'
ASA_SHOW_IP = 'show ip address'


PAN_SET_CLI_PAGER_OFF = 'set cli pager off'
PAN_SHOW_ARP = 'show arp all'

# ------
# ERRORS
# ------

OPERATIONAL_TIMEOUT = '.*Operation timed out\r\r\n.*'
ERROR = '.*ERROR:.*'
BASH_ERROR = '.*bash:.*'
PAN_INVALID_SYNTAX = '.*Invalid syntax.*'
PAN_UNKNOWN_CMD = '.*Unknown command:.*'


def get_ssh_session(host, username):
    ssh_session = 'ssh %s@%s' % (username, host)
    child = spawnu(ssh_session)
    passwd = 0

    while True:
        # 99 = timed out
        # 98 = connection refused
        # 97 = bad ssh key
        # 96 = using ssh v1
        # 95 = password denied
        # 94 = permission denied
        s = child.expect([SSH_NEW_KEY,
                          SSH_OUTDATED_KEX,
                          PASSWORD,
                          PERMISSION_DENIED,
                          GT_PROMPT,
                          HASH_PROMPT,
                          GT_PROMPT_W_S,
                          HASH_PROMPT_W_S,
                          TIMEOUT,
                          SSH_REFUSED,
                          SSH_BAD_KEY,
                          SSH_OUTDATED_PROTOCOL,
                          OPERATIONAL_TIMEOUT,
                          EOF])

        if s == 0:
            child.sendline('yes')
            continue

        elif s == 1:
            # print('INFO: Using outdated SSH Key Exchange for %s\nKEX: diffie-hellman-group1-sha1' % host)
            ssh_session = 'ssh %s@%s -oKexAlgorithms=+diffie-hellman-group1-sha1' % (username, host)  # outdated kex
            child = spawnu(ssh_session)
            continue

        elif s == 2:
            if passwd < 0:
                return 95, ''
            child.sendline(settings.SVC_ACCOUNT_PASSWD)
            passwd += 1
            continue

        elif s == 3:
            return 94, ''

        elif s == 4:
            return child, GT_PROMPT

        elif s == 5:
            return child, HASH_PROMPT

        elif s == 6:
            return child, GT_PROMPT_W_S

        elif s == 7:
            return child, HASH_PROMPT_W_S

        elif s == 8:
            return 99, ''

        elif s == 9:
            return 98, ''

        elif s == 10:
            return 97, ''

        elif s == 11:
            return 96, ''

        elif s == 12:
            return 99, ''

        elif s == 12:
            return 93, ''

        else:
            return 1, ''


def discover_os(ssh_session, prompt):
    infrastructure_os = dict()
    ssh_session.sendline(IOS_TERMLEN0)
    cmd_response = ssh_session.expect([TIMEOUT, PAN_UNKNOWN_CMD, ERROR, BASH_ERROR, prompt])

    if cmd_response == 1:
        ssh_session.sendline(PAN_SET_CLI_PAGER_OFF)
        it_is_panos = ssh_session.expect([TIMEOUT, prompt])
        if it_is_panos == 1:
            infrastructure_os = {'os': 'panos'}
    if cmd_response == 2:
        ssh_session.sendline(ASA_TERMPAGER0)
        cmd_response = ssh_session.expect([TIMEOUT, prompt, ERROR])
        if cmd_response == 1:
            infrastructure_os = {'os': 'asaos'}
        if cmd_response == 2:
            ssh_session.sendline(ENABLE)
            cmd_response = ssh_session.expect([TIMEOUT, PASSWORD, PASSWORD_W_S])
            if cmd_response == 1 or cmd_response == 2:
                ssh_session.sendline(settings.SVC_ACCOUNT_PASSWD)
                cmd_response = ssh_session.expect([TIMEOUT, PASSWORD, PASSWORD_W_S, HASH_PROMPT, HASH_PROMPT_W_S])
                if cmd_response == 1 or cmd_response == 2:
                    print('ERROR: password is incorrect')
                    return
                if cmd_response == 3:
                    prompt = HASH_PROMPT
                if cmd_response == 4:
                    prompt = HASH_PROMPT_W_S
                ssh_session.sendline(ASA_TERMPAGER0)
                cmd_response = ssh_session.expect([TIMEOUT, prompt])
                if cmd_response == 1:
                    infrastructure_os = {'os': 'asaos'}
    if cmd_response == 3:
        infrastructure_os = {'os': 'linux'}
    elif cmd_response == 4:
        infrastructure_os = {'os': 'ios'}

    return infrastructure_os, ssh_session, prompt
