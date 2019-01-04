from pexpect import spawnu, TIMEOUT, EOF, exceptions as pexceptions
from subprocess import check_output, CalledProcessError
from re import search, sub
import platform
import ipaddress

# ----------------
# pexpect SSH info
# ----------------
SSH_NEW_KEY = '.Are you sure you want to continue connecting (yes/no)?'
SSH_BAD_KEY = 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!'
SSH_REFUSED = 'Connection refused'
SSH_OUTDATED_KEX = '.no matching key exchange method found'
SSH_OUTDATED_CIPHER = '.no matching cipher found. Their offer: aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc'
SSH_OUTDATED_PROTOCOL = 'Protocol major versions differ: 2 vs. 1\\r\\r\\n'
PASSWORD = '.*[P|p]assword.*'
PERMISSION_DENIED = 'Permission denied, please try again.'
NETWORK_UNREACHABLE = '.Network is unreachable.'
INVALID_KEY_LENGTH = '.Invalid key length.'

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
IOS_SWITCH_SHOW_MODEL = 'show version | include Model Number'
IOSx_SWITCH_SHOW_MODEL = 'show version | include Model number'
IOS_S72033_RP_SHOW_MODEL = 'show version | include cisco WS-'
IOS_C7200_SHOW_MODEL = 'show version | in processor'
IOS_RTR_SHOW_MODEL = 'show version | include \*'
IOS_SWITCH_SHOW_SERIALNUM = 'show version | include System Serial Number'
IOSx_SWITCH_SHOW_SERIALNUM = 'show version | include System serial number'
IOS_S72033_RP_SHOW_SERIALNUM = 'show version | include Processor board ID'
IOS_RTR_SHOW_SERIALNUM = 'show version | include Processor board ID'
IOS_SHOW_LICS = 'show version | include License Level'
IOS_LAST_RESORT_SHOW_MODEL = 'show version  | include (WS)'


# --------------------
# Cisco NX-OS commands
# --------------------
NXOS_SHOW_LOCAL_CONNECTIONS = 'show ip route direct | include attached'
NXOS_SHOW_ARP = 'show ip arp | exclude INCOMPLETE'


# ------------------
# Cisco ASA commands
# ------------------
ASA_TERMPAGER0 = 'terminal pager 0'
ASA_SHOWARP = 'show arp'
ASA_SHOW_OS = 'show version | in Adaptive'
ASA_SHOW_LOCAL_CONNECTIONS = 'show route | in C'
ASA_SHOW_XLATE = 'show xlate'  # todo: 8.2 = > may need to revisit
ASA_SHOW_CONN = 'show conn'
ASA_SHOW_SERIALNUM = 'show version | include Serial Number:'
ASA_SHOW_MODEL = 'show version | include Hardware:'
ASA_SHOW_INTERFACE = 'show running-config interface'


# ------------------
# Palo Alto commands
# ------------------

PAN_SHOW_INTERFACES_LOGICAL = 'show interface logical'
PAN_SHOW_RUN_NAT = 'show running nat-policy'
PAN_SHOW_SUBNETS = 'show routing route type connect | match C '
PAN_SHOW_SYS_INFO = 'show system info'
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


# ------------
# COMMON REGEX
# ------------

ipaddr_regex = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

subnet_regex = r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d+)'

mac_addr_regex = r'(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})'


def is_subnet(net):
    try:
        ipaddress.ip_network(net)
        return True
    except ValueError:
        return False


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_ssh_session(host, username, password):
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
        # 93 = EOF
        # 92 = network unreachable
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
                          SSH_OUTDATED_CIPHER,
                          NETWORK_UNREACHABLE,
                          INVALID_KEY_LENGTH,
                          EOF])
        print(s)

        if s == 0:
            child.sendline('yes')
            continue

        elif s == 1:
            # print('INFO: Using outdated SSH Key Exchange for %s\nKEX: diffie-hellman-group1-sha1' % host)
            ssh_session = 'ssh %s@%s -oKexAlgorithms=+diffie-hellman-group1-sha1' % (username, host)  # outdated kex
            child = spawnu(ssh_session)
            continue

        elif s == 2:
            if passwd > 0:
                return 95, ''
            child.sendline(password)
            passwd += 1
            continue

        elif s == 3:
            child.close()
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
            child.close()
            return 99, ''

        elif s == 9:
            child.close()
            return 98, ''

        elif s == 10 or s == 15:
            child.close()
            return 97, ''

        elif s == 11:
            child.close()
            return 96, ''

        elif s == 12:
            child.close()
            return 99, ''

        elif s == 12:
            child.close()
            return 93, ''

        elif s == 13:
            ssh_session += ' -c aes128-cbc'  # try aes128-cbc
            child = spawnu(ssh_session)
            continue

        elif s == 14:
            child.close()
            return 92, ''

        elif s == 16:
            child.close()
            return 93, ''

        else:
            print(child.before)
            child.close()
            return 1, ''


def discover_os(ssh_session, prompt, password):
    infrastructure_os = dict()
    ssh_session.sendline(IOS_TERMLEN0)
    cmd_response = ssh_session.expect([TIMEOUT, PAN_UNKNOWN_CMD, ERROR, BASH_ERROR, prompt])

    if cmd_response == 1:
        ssh_session.sendline(PAN_SET_CLI_PAGER_OFF)
        cmd_response = ssh_session.expect([TIMEOUT, prompt])
        if cmd_response == 1:
            infrastructure_os = {'os': 'panos'}
    if cmd_response == 2:
        ssh_session.sendline(ENABLE)
        cmd_response = ssh_session.expect([TIMEOUT, PASSWORD])
        if cmd_response == 1:
            ssh_session.sendline(password)
            cmd_response = ssh_session.expect([TIMEOUT, PASSWORD, HASH_PROMPT, HASH_PROMPT_W_S])
            if cmd_response == 1:
                print('ERROR: password is incorrect')
                return
            if cmd_response == 2:
                prompt = HASH_PROMPT
            if cmd_response == 3:
                prompt = HASH_PROMPT_W_S
            ssh_session.sendline(IOS_TERMLEN0)
            cmd_response = ssh_session.expect([TIMEOUT, ERROR, prompt])
            if cmd_response == 1:
                ssh_session.sendline(ASA_TERMPAGER0)
                cmd_response = ssh_session.expect([TIMEOUT, prompt])
                if cmd_response == 1:
                    infrastructure_os = {'os': 'asaos'}
            if cmd_response == 2:
                ssh_session.sendline(SHOW_OS)
                ssh_session.expect([TIMEOUT, prompt])
                show_os_buff = ssh_session.before
                if 'NX-OS' in show_os_buff:
                    infrastructure_os = {'os': 'nxos'}
                elif 'IOS' in show_os_buff:
                    infrastructure_os = {'os': 'ios'}
                else:
                    infrastructure_os = {'os': 'unknown'}
    if cmd_response == 3:
        infrastructure_os = {'os': 'linux'}
    elif cmd_response == 4:
        ssh_session.sendline(SHOW_OS)
        ssh_session.expect([TIMEOUT, prompt])
        show_os_buff = ssh_session.before
        if 'NX-OS' in show_os_buff:
            infrastructure_os = {'os': 'nxos'}
        elif 'IOS' in show_os_buff:
            infrastructure_os = {'os': 'ios'}
        else:
            infrastructure_os = {'os': 'unknown'}

    print(infrastructure_os)
    return infrastructure_os, ssh_session, prompt


def lookup_mac_vendor(mac_lookup_string):
    if platform.system() == 'Darwin':
        nmap_mac_prefixes = '/usr/local/Cellar/nmap/7.60/share/nmap/nmap-mac-prefixes'
    else:
        nmap_mac_prefixes = '/usr/share/nmap/nmap-mac-prefixes'

    try:
        mac_vendor_lookup = check_output(['grep',
                                          mac_lookup_string[:6].upper(),
                                          nmap_mac_prefixes])

        mac_vendor_lookup = str(mac_vendor_lookup.strip())
        mac_vendor = ' '.join(mac_vendor_lookup.strip('\'').split(' ')[1:])

    except CalledProcessError:
        mac_vendor = None

    return mac_vendor


def kill_ssh_session(ssh_session):
    try:
        ssh_session.close()
    except pexceptions.ExceptionPexpect as e1:
        print('INFO: %s' % str(e1))
        try:
            ssh_session.close()
        except pexceptions.ExceptionPexpect as e2:
            print('KILL_SSH_SESSION ERROR: %s' % str(e2))


def get_cdp_list(cdp_data, os='ios'):
    cdp_list = list()

    if cdp_data:
        for element in cdp_data:

            # empty discovery list
            discovery_list = []

            # search for the device id
            reg_device_id = search(r'(Device ID:.+?)\n', element)

            try:

                # add the device id to the list
                discovery_list += [sub(r':\s+', ':', reg_device_id.group(0).strip())]

            except AttributeError:
                discovery_list.append('Device ID:')

            # search for the ip address
            reg_entry_addrs = search(ipaddr_regex, element)

            try:

                # add the ip  to the list
                discovery_list.append('IP:%s' % str(reg_entry_addrs.group(0).strip('\n')))
            except AttributeError:
                discovery_list.append('IP:')

            # search for the platform information
            reg_platform = search(r'(Platform:.+?)\n', element)

            try:

                # parse platform info and clean it up
                platform_line = sub(r':\s+', ':', reg_platform.group(0).strip())
                platform_capabilities = platform_line.split(',  ')

                # add the platform info to the list

                if os == 'nxos':
                    platform_capabilities = platform_capabilities[0].split(',')
                    discovery_list.append(platform_capabilities[0].lstrip())
                    discovery_list.append(platform_capabilities[1].lstrip())
                else:
                    discovery_list.append(platform_capabilities[0])
                    discovery_list.append(platform_capabilities[1])
            except AttributeError:
                discovery_list.append('Platform:')
                discovery_list.append('Capabilities:')

            # search for interface information
            reg_int = search(r'(Interface:.+?)\n', element)

            try:

                # parse interface info and clean it up
                int_line = sub(r':\s+', ':', reg_int.group(0).strip())
                interface_port_id = int_line.split(',  ')

                # add interface info to the list

                if os == 'nxos':
                    interface_port_id = interface_port_id[0].split(',')
                    discovery_list.append(interface_port_id[0].lstrip())
                    discovery_list.append(interface_port_id[1].lstrip())
                else:
                    discovery_list.append(interface_port_id[0])
                    discovery_list.append(interface_port_id[1])
            except AttributeError:
                discovery_list.append('Interface:')
                discovery_list.append('Port ID (outgoing port):')

            # search for advertisement info
            reg_advertisment_ver = search(r'(advertisement version:.+?)\n', element)

            try:

                # parse advertisement info and clean it up
                discovery_list += [sub(r':\s+', ':', reg_advertisment_ver.group(0).strip())]
            except AttributeError:
                discovery_list.append('advertisement version:')

            # search for protocol information
            reg_protocol_hello = search(r'(Protocol Hello:.+?)\n', element)

            try:

                # parse protocol info and clean it up
                discovery_list += [sub(r':\s+', ':', reg_protocol_hello.group(0).strip())]
            except AttributeError:
                discovery_list.append('Protocol Hello:')

            # search for vtp mgnt domain
            reg_vtp_mgnt = search(r'(VTP Management Domain:.+?)\n', element)

            try:

                # parse vtp mgnt info and clean it up
                discovery_list += [sub(r':\s+', ':', reg_vtp_mgnt.group(0).strip())]
            except AttributeError:
                discovery_list.append('VTP Management Domain:')

            # search for native vlan info
            reg_native_vlan = search(r'(Native VLAN:.+?)\n', element)

            try:

                # parse native vlan info and clean it up
                discovery_list += [sub(r':\s+', ':', reg_native_vlan.group(0).strip())]
            except AttributeError:
                discovery_list.append('Native VLAN:')

            # search for duplex info
            reg_duplex = search(r'(Duplex:.+?)\n', element)

            try:

                # parse duplex info and clean it up
                discovery_list += [sub(r':\s+', ':', reg_duplex.group(0).strip())]
            except AttributeError:
                discovery_list.append('Duplex:')

            # search for power info
            reg_power_drawn = search(r'(Power drawn:.+?)\n', element)

            # discovery_dictionary = dict()

            try:
                # parse power info and clean it up
                discovery_list += [sub(r':\s+', ':', reg_power_drawn.group(0).strip())]
            except AttributeError:
                discovery_list.append('Power drawn:')

                # build the discovery protocol dictionary from the list
            discovery_dictionary = dict(map(str, x.split(':')) for x in discovery_list)

            # iterate the key, value pairs and change empty value to None
            for k, v in discovery_dictionary.items():
                if v is '':
                    discovery_dictionary[k] = None

            if discovery_dictionary['Device ID'] is not None:
                if discovery_dictionary not in cdp_list:
                    cdp_list.append(discovery_dictionary)
    return cdp_list
