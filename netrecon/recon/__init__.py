from netrecon import shared
from pexpect import TIMEOUT
from re import search, compile as recompile
from netaddr import IPAddress
import time


def host_discovery(system_address, username, password):
    ssh_session, prompt = shared.get_ssh_session(system_address, username, password)
    data = None
    # print('got session with %s' % system_address)
    # 99 = timed out
    # 98 = connection refused
    # 97 = bad ssh key
    # 96 = using ssh v1
    # 95 = password denied
    # 94 = permission denied
    # 93 = EOF
    # 92 = network unreachable
    # 1 = could not connect

    if ssh_session == 99:
        return 99
    if ssh_session == 98:
        return 98
    if ssh_session == 97:
        return 97
    if ssh_session == 96:
        return 96
    if ssh_session == 95:
        return 95
    if ssh_session == 94:
        return 94
    if ssh_session == 93:
        return 93
    if ssh_session == 92:
        return 92
    if ssh_session == 1:
        return 1
    infrastructure_os, ssh_session, prompt = shared.discover_os(ssh_session, prompt, password)
    try:
        if infrastructure_os['os']:
            if infrastructure_os['os'] == 'panos':
                data = get_panos_hosts(ssh_session, prompt)
            elif infrastructure_os['os'] == 'ios':
                data = get_ios_hosts(ssh_session, prompt)
            elif infrastructure_os['os'] == 'nxos':
                data = get_nxos_hosts(ssh_session, prompt)
            elif infrastructure_os['os'] == 'asaos':
                data = get_asa_hosts(ssh_session, prompt)
            elif infrastructure_os['os'] == 'linux':
                data = infrastructure_os['os']
                shared.kill_ssh_session(ssh_session)
    except KeyError as e:
        print('HOST_DISCOVERY EXCEPTION ERROR: %s' % str(e))
    return data


def get_panos_hosts(ssh_session, prompt):
    data = dict()
    host_list = list()
    subnet_list = list()
    system_ip_list = list()
    nat_list = list()

    model = None
    serial = None
    sw_version = None

    ssh_session.expect([TIMEOUT, prompt])
    ssh_session.sendline(shared.PAN_SHOW_INTERFACES_LOGICAL)
    ssh_session.expect([TIMEOUT, prompt])
    show_interfaces_buff = ssh_session.before

    ssh_session.expect([TIMEOUT, prompt])
    ssh_session.sendline(shared.PAN_SHOW_ARP)
    ssh_session.expect([TIMEOUT, prompt])
    arp_buff = ssh_session.before

    ssh_session.expect([TIMEOUT, prompt])
    ssh_session.sendline(shared.PAN_SHOW_SUBNETS)
    ssh_session.expect([TIMEOUT, prompt])
    subnets_buff = ssh_session.before

    ssh_session.sendline(shared.PAN_SHOW_SYS_INFO)
    ssh_session.expect([TIMEOUT, prompt])
    sys_info_buff = ssh_session.before

    ssh_session.sendline(shared.PAN_SHOW_RUN_NAT)
    ssh_session.expect([TIMEOUT, prompt])
    nat_buff = ssh_session.before

    shared.kill_ssh_session(ssh_session)

    interfaces = show_interfaces_buff.split('------------------- ----- ---- ---------------- ------------------------ ------ ------------------')
    interfaces_split = interfaces[1].split('\r\n')

    for e in interfaces_split:
        if e != '':
            entry = e.rstrip().split()
            if len(entry) == 7:
                d = {'system_ip_address': entry[6], 'vlan': int(entry[5]), 'name': entry[0], 'zone': entry[3]}
                if d not in system_ip_list:
                    system_ip_list.append(d)

    arp = arp_buff.split('--------------------------------------------------------------------------------')
    split_arp = arp[1].split('\r\n')
    for e in split_arp:
        if e != '':
            entry = e.rstrip().split()
            if len(entry) == 6:
                if entry[4] == 'c':
                    mac_addr = entry[2].replace(':', '')
                    mac_vendor = shared.lookup_mac_vendor(mac_addr)
                    host_dict = {'adjacency_interface': entry[0],
                                 'host_address': entry[1],
                                 'mac_address': mac_addr,
                                 'port': entry[3],
                                 'mac_vendor': mac_vendor
                                 }
                    host_list.append(host_dict)

    subnets_buff_split = subnets_buff.split('\r\n')
    subnets_buff_split.pop(-1)
    for i in subnets_buff_split[2:]:
        sn = i.split()
        if shared.is_subnet(sn[0]):
            local_subnet_dict = {'subnet': '%s' % sn[0],
                                 'source_interface': sn[-1]}
            if local_subnet_dict not in subnet_list:
                subnet_list.append(local_subnet_dict)

    sys_info_buff_splt = sys_info_buff.split('^(\r\n)')
    for i in sys_info_buff_splt:
        model_match = search(r'(model:\s+)([^\s]+)', i)
        serial_match = search(r'(serial:\s+)([^\s]+)', i)
        sw_version_match = search(r'(sw-version:\s+)([^\s]+)', i)

        if model_match:
            model = model_match.group(2)
        if serial_match:
            serial = serial_match.group(2)
        if sw_version_match:
            sw_version = sw_version_match.group(2)

    nat_buff_split = nat_buff.strip().split('{')
    nat_buff_split.pop(0)
    for i in nat_buff_split:
        i_split = i.split('}')
        i_split.pop(1)
        nat_line = i_split[0].split('\r\n')
        d = {}
        for line in nat_line:
            if line:
                line_split = line.split()
                if line_split[0] == 'nat-type':
                    d['nat_type'] = line_split[1].rstrip(';')
                if line_split[0] == 'from':
                    d['from'] = line_split[1].rstrip(';')
                if line_split[0] == 'source':
                    if '[' in line_split[1]:
                        line_split.pop(-1)
                        d['source'] = line_split[2:]
                    else:
                        d['source'] = line_split[1].rstrip(';')
                if line_split[0] == 'to':
                    d['to'] = line_split[1].rstrip(';')
                if line_split[0] == 'to-interface':
                    d['to_interface'] = line_split[1].rstrip(';')
                if line_split[0] == 'destination':
                    if '[' in line_split[1]:
                        line_split.pop(-1)
                        d['destination'] = line_split[2:]
                    else:
                        d['destination'] = line_split[1].rstrip(';')
                if line_split[0] == 'service':
                    d['service'] = line_split[1].rstrip(';')
                if line_split[0] == 'translate-to':
                    line_split = line.split('"')
                    line_split.pop(-1)
                    d['translate_to'] = line_split[1]
        if d not in nat_list:
            nat_list.append(d)

    system_info = {'system_model': model,
                   'system_serial': serial,
                   'license': None,
                   'system_sw_version': 'PAN-OS %s' % sw_version}
    data['nat_list'] = nat_list
    data['system_ip_list'] = system_ip_list
    data['system_info'] = system_info
    data['subnet_list'] = subnet_list
    data['host_list'] = host_list
    return data


def get_asa_hosts(ssh_session, prompt):
    system_info = dict()
    data = dict()
    host_list = list()
    subnet_list = list()
    system_ip_list = list()
    nat_list = list()

    ssh_session.expect([TIMEOUT, prompt])
    ssh_session.sendline(shared.ASA_SHOW_OS)
    ssh_session.expect([TIMEOUT, prompt])
    os_software = ssh_session.before

    ssh_session.sendline(shared.ASA_SHOW_SERIALNUM)
    ssh_session.expect([TIMEOUT, prompt])
    time.sleep(.1)
    asa_sn = ssh_session.before

    ssh_session.sendline(shared.ASA_SHOW_MODEL)
    ssh_session.expect([TIMEOUT, prompt])
    time.sleep(.1)
    asa_model_buff = ssh_session.before

    ssh_session.sendline(shared.ASA_SHOW_INTERFACE)
    ssh_session.expect([TIMEOUT, prompt])
    time.sleep(.1)
    asa_interfaces_buff = ssh_session.before

    ssh_session.sendline(shared.ASA_SHOW_LOCAL_CONNECTIONS)
    ssh_session.expect([TIMEOUT, prompt])
    time.sleep(.1)
    local_subnets_buff = ssh_session.before
    local_subnets_lines = local_subnets_buff.split('\r\n')

    ssh_session.sendline(shared.ASA_SHOWARP)
    ssh_session.expect([TIMEOUT, prompt])
    time.sleep(.1)
    arp_buff = ssh_session.before
    arp_lines = arp_buff.split('\t')

    ssh_session.sendline(shared.ASA_SHOW_XLATE)
    if ssh_session.expect([TIMEOUT, '.Invalid input detected.', prompt]) == 1:
        ssh_session.expect([TIMEOUT, prompt])
        ssh_session.sendline('show xlate')
    ssh_session.expect([TIMEOUT, prompt])
    nat_buff = ssh_session.before

    shared.kill_ssh_session(ssh_session)

    asa_interfaces_split = asa_interfaces_buff.split('!')
    asa_interfaces_split.pop(0)

    for l in asa_interfaces_split:
        int_line = l.split('\r\n')
        d = {}
        for line in int_line:
            if line:
                x = line.split()
                if x[0] == 'nameif':
                    nameif = x[1]
                    d['nameif'] = nameif
                if x[0] == 'ip':
                    ip_addr = x[2]
                    net_mask = x[3]
                    d['system_ip_address'] = ip_addr
                    d['net_mask'] = net_mask
                if x[0] == 'vlan':
                    tag = int(x[1])
                    d['vlan'] = tag
                if x[0] == 'interface':
                    interface = x[1]
                    d['interface'] = interface
        if 'nameif' in d:
            if 'tag' not in d:
                d['vlan'] = 0
            if d not in system_ip_list:
                system_ip_list.append(d)

    for subnet_line in local_subnets_lines:
        subnet_line_list = list(filter(None, subnet_line.split(' ')))
        try:
            ip_addr = subnet_line_list[1]
            mask = subnet_line_list[2]
            interface = subnet_line_list[-1:][0]
        except IndexError:
            continue
        if shared.is_valid_ip(ip_addr):
            if shared.is_subnet(mask):
                local_subnet_dict = {'subnet': '%s/%s' % (ip_addr, IPAddress(mask).netmask_bits()),
                                     'source_interface': interface}
                if local_subnet_dict not in subnet_list:
                    subnet_list.append(local_subnet_dict)
    for a in arp_lines:

        arp_split = a.split(' ')
        try:
            mac_addr = arp_split[2].replace('.', '')
        except IndexError:
            continue
        mac_vendor = shared.lookup_mac_vendor(mac_addr)
        host_dict = {'host_address': arp_split[1],
                     'mac_address': mac_addr,
                     'adjacency_interface': arp_split[0],
                     'mac_vendor': mac_vendor}
        if host_dict not in host_list:
            host_list.append(host_dict)

    asa_model_split = asa_model_buff.split('\r\n')
    for asa_model in asa_model_split:
        asa_model_match = search(r'^Hardware:\s+([^\s]+)', asa_model)
        if asa_model_match:
            if asa_model_match.group(1).endswith(','):
                asa_model = asa_model_match.group(1)[:-1]
            else:
                asa_model = asa_model_match.group(1)
            system_info['system_model'] = asa_model
    asa_sn_split = asa_sn.split('\r\n')
    for asa_sn in asa_sn_split:
        asa_serial_match = search(r'^Serial\s+Number\s*:\s+([^\s]+)', asa_sn)
        if asa_serial_match:
            system_info['system_serial'] = asa_serial_match.group(1)
    os_software_split = os_software.split('\r\n')
    for os_software in os_software_split:
        asa_os_ver_match = search(r'(^Cisco\s+Adaptive\s+Security\s+Appliance)', os_software)
        if asa_os_ver_match:
            system_info['system_sw_version'] = os_software.rstrip()
    nat_lines = recompile(r'TCP|UDP|NAT').split(nat_buff)
    if not nat_lines:
        nat_lines = nat_buff.split('\r\n')
    nat_lines.pop(-1)
    nat_lines = nat_lines[2:]
    for l in nat_lines:
        d = {}
        split_flags = l.split('flags')
        if 'sr' in split_flags[1]:
            split_to = str(split_flags[0]).split('to')
            to_int = split_to[1].split(':')
            d['to_int:'] = to_int[0].strip()
            d['to_list:'] = [x.rstrip().strip() for x in to_int[1].split(',')]
            split_from = str(split_to[0]).split('from')
            from_int = split_from[1].split(':')
            d['from_int:'] = from_int[0].strip()
            d['from_list:'] = [x.rstrip().strip() for x in from_int[1].split(',')]
            nat_list.append(d)
    data['nat_list'] = nat_list
    data['system_ip_list'] = system_ip_list
    data['system_info'] = system_info
    data['subnet_list'] = subnet_list
    data['host_list'] = host_list
    return data


def get_nxos_hosts(ssh_session, prompt):
    data = dict()
    system_ip_list = list()
    host_list = list()
    subnet_list = list()
    mac_list = list()
    system_info = dict()

    sw_version = None

    ssh_session.sendline(shared.SHOW_OS)
    ssh_session.expect([TIMEOUT, prompt])
    os_software = ssh_session.before

    os_software_split = os_software.split('\r\n')
    for i in os_software_split:
        nxos_ver = search(r'(^Cisco\s+Nexus\s+Operating)', i)
        if nxos_ver:
            sw_version = i.rstrip()

    system_info['system_sw_version'] = sw_version

    ssh_session.sendline('show version | include "Processor Board ID"')
    ssh_session.expect([TIMEOUT, prompt])
    switch_sn = ssh_session.before
    system_info['system_serial'] = switch_sn.split('show version | include "Processor Board ID"')[1].split('\r\n')[1].split('ID')[1].strip()

    ssh_session.sendline('show version  | section Hardware')
    ssh_session.expect([TIMEOUT, prompt])
    switch_model = ssh_session.before
    system_info['system_model'] = switch_model.split('show version  | section Hardware')[1].split('Hardware')[1].split('\r\n')[1].strip()

    ssh_session.sendline(shared.IOS_SHOWIPINTBR)
    ssh_session.expect([TIMEOUT, prompt])
    system_ip_address_buff = ssh_session.before

    ssh_session.sendline(shared.NXOS_SHOW_LOCAL_CONNECTIONS)
    ssh_session.expect([TIMEOUT, prompt])
    local_subnets_buff = ssh_session.before

    ssh_session.sendline(shared.IOS_SHOW_CDP_DETAIL)
    ssh_session.expect([TIMEOUT, prompt])
    cdp_buff = ssh_session.before
    cdp_data = str(cdp_buff).split('-------------------------')

    ssh_session.sendline(shared.NXOS_SHOW_ARP)
    ssh_session.expect([TIMEOUT, prompt])
    arp_buff = ssh_session.before

    ssh_session.sendline(shared.IOS_SHOW_CAM)
    ssh_session.expect([TIMEOUT, prompt])
    cam_buff = ssh_session.before

    shared.kill_ssh_session(ssh_session)

    addr_line_split = system_ip_address_buff.split('Interface            IP Address      Interface Status')
    addrs_nl_split = addr_line_split[1].split('\r\n')
    addrs_nl_split.pop(-1)
    for addrs_line in addrs_nl_split:
        if addrs_line:
            line = addrs_line.split()
            d = {'system_ip_address': line[1],
                 'name': line[0],
                 'status': line[2]
                 }
            if d not in system_ip_list:
                system_ip_list.append(d)

    local_subnets = local_subnets_buff.split('show ip route direct | include attached')[1]
    local_subnets_lines = local_subnets.split('\r\n')
    local_subnets_lines.pop(0)
    local_subnets_lines.pop(-1)
    for subnet_line in local_subnets_lines:
        if subnet_line:
            subnet_split = subnet_line.split(',')
            if shared.is_subnet(subnet_split[0]):
                subnet = subnet_split[0]
                source_int = None
                local_subnet_dict = {'subnet': subnet,
                                     'source_interface': source_int}
                if local_subnet_dict not in subnet_list:
                    subnet_list.append(local_subnet_dict)

    cdp_list = shared.get_cdp_list(cdp_data, 'nxos')

    cam_lines = cam_buff.split('---------+-----------------+--------+---------+------+----+------------------')[1].split('\r\n')
    cam_lines.pop(-1)
    for cam_line in cam_lines:
        cam_line = cam_line.split()
        if cam_line:
            try:
                if cam_line[0] in ('Legend:', '*', 'age', 'VLAN'):
                    continue
                mac_vendor = shared.lookup_mac_vendor(cam_line[2].replace('.', ''))
            except IndexError as mac_vendor_error:
                print(mac_vendor_error)
                print('----------------------------------------------')
                print('IndexError: mac_vendor - %s' % system_info)
                print('ssh_session args: %s' % ssh_session.args)
                return data
            try:
                vlan = int(cam_line[1])
            except ValueError:
                vlan = cam_line[1]
            mac_addr_dict = {'mac_address': cam_line[2],
                             'type': cam_line[3],
                             'port': cam_line[-1],
                             'vlan': vlan,
                             'mac_vendor': mac_vendor}
            if mac_addr_dict not in mac_list:
                mac_list.append(mac_addr_dict)
                continue

    arp_lines = arp_buff.split('Address         Age       MAC Address     Interface')
    arp_lines = arp_lines[1].split('\r\n')
    arp_lines.pop(-1)
    for arp_line in arp_lines:
        if arp_line:
            line = arp_line.split()
            for x in mac_list:
                if x['mac_address'] == line[2]:
                    host_dict = {'host_address': line[0],
                                 'mac_address': line[2],
                                 'adjacency_interface': line[-1],
                                 'mac_vendor': x['mac_vendor'],
                                 'type': x['type'],
                                 'port': x['port'],
                                 'vlan': x['vlan']}

                    if host_dict not in host_list:
                        host_list.append(host_dict)

    data['system_ip_list'] = system_ip_list
    data['system_info'] = system_info
    data['subnet_list'] = subnet_list
    data['host_list'] = host_list
    data['discovery_list'] = cdp_list

    return data


def get_ios_hosts(ssh_session, prompt):
    data = dict()
    system_ip_list = list()
    host_list = list()
    subnet_list = list()
    mac_list = list()
    system_info = dict()
    sw_version = None

    ssh_session.sendline(shared.SHOW_OS)
    ssh_session.expect([TIMEOUT, prompt])
    os_software = ssh_session.before

    os_software_split = os_software.split('\r\n')
    for i in os_software_split:
        old_ios = search(r'^IOS\s+\(tm\)', i)
        ios_ver = search(r'(^Cisco\s+IOS\s+Software,)', i)
        if old_ios or ios_ver:
            sw_version = i.rstrip()

    system_info['system_sw_version'] = sw_version
    if  system_info['system_sw_version'] in ('Version 12.2',
                                             'Version 12.4(24)T5',
                                             'IOS-XE',
                                             'C3900e'):
        ssh_session.sendline(shared.IOS_S72033_RP_SHOW_SERIALNUM)
        ssh_session.expect([TIMEOUT, prompt])
        switch_sn = ssh_session.before
        system_info['system_serial'] = switch_sn.split('show version | include Processor board ID\r\nProcessor board ID')[1].split('\r\n')[0].lstrip()
    elif 'Version 15.2' in system_info['system_sw_version']:
        ssh_session.sendline(shared.IOSx_SWITCH_SHOW_SERIALNUM)
        ssh_session.expect([TIMEOUT, prompt])
        switch_sn = ssh_session.before
        try:
            system_info['system_serial'] = switch_sn.split('\r\n')[1].split()[1]
        except IndexError as system_info_error:
            print(system_info_error)
            print('----------------------------------------------')
            print('IndexError: system_info[\'system_serial\'] - %s' % system_info)
            print('ssh_session args: %s' % ssh_session.args)
            return data
    else:
        ssh_session.sendline(shared.IOS_SWITCH_SHOW_SERIALNUM)
        ssh_session.expect([TIMEOUT, prompt])
        switch_sn = ssh_session.before
        system_info['system_serial'] = switch_sn.split('System Serial Number')[2].split(':')[1].split()[0]

    if 'Version 12.2' in system_info['system_sw_version']:
        ssh_session.sendline(shared.IOS_S72033_RP_SHOW_MODEL)
        ssh_session.expect([TIMEOUT, prompt])
        switch_model = ssh_session.before
        system_info['system_model'] = switch_model.split('\r\n')[1].split()[1]
    elif '7200 Software' in system_info['system_sw_version'] or 'IOS-XE' in system_info['system_sw_version']:
        ssh_session.sendline(shared.IOS_C7200_SHOW_MODEL)
        ssh_session.expect([TIMEOUT, prompt])
        switch_model = ssh_session.before
        system_info['system_model'] = switch_model.split('\r\n')[1].split()[1]
    elif 'Version 15.2' in system_info['system_sw_version']:
        ssh_session.sendline(shared.IOSx_SWITCH_SHOW_MODEL)
        ssh_session.expect([TIMEOUT, prompt])
        switch_model = ssh_session.before
        system_info['system_model'] = switch_model.split('\r\n')[1].split()[1]
    else:
        ssh_session.sendline(shared.IOS_SWITCH_SHOW_MODEL)
        ssh_session.expect([TIMEOUT, prompt])
        switch_model = ssh_session.before
        system_info['system_model'] = switch_model.split('Model Number')[2].split(':')[1].split()[0]

    ssh_session.sendline(shared.IOS_SHOWIPINTBR)
    ssh_session.expect([TIMEOUT, prompt])
    system_ip_address_buff = ssh_session.before

    ssh_session.sendline(shared.IOS_SHOW_LOCAL_CONNECTIONS)
    ssh_session.expect([TIMEOUT, prompt])
    local_subnets_buff = ssh_session.before

    ssh_session.sendline(shared.IOS_SHOW_ARP)
    ssh_session.expect([TIMEOUT, prompt])
    arp_buff = ssh_session.before
    arp_lines = arp_buff.split('\r\n')[5:]
    arp_lines.pop(-1)

    ssh_session.sendline(shared.IOS_SHOW_CAM)
    if ssh_session.expect([TIMEOUT, '.Invalid input detected.', prompt]) == 1:
        ssh_session.expect([TIMEOUT, prompt])
        ssh_session.sendline('show mac-address-table | exclude All')
        try_again = ssh_session.expect([TIMEOUT, prompt, '.Invalid input detected.'])
        if try_again == 1:
            cam_buff = ssh_session.before
            cam_lines = cam_buff.split('------+----------------+--------+-----+--------------------------')[1].split('\r\n')
        else:
            cam_lines = ['']
    else:
        cam_buff = ssh_session.before
        if '4500 L3' in system_info['system_sw_version'] or '4000 L3' in system_info['system_sw_version']:
            cam_lines = cam_buff.split('-------+---------------+--------+---------------------+--------------------')[1].split('\r\n')
        elif 'C3560' in system_info['system_sw_version'] or\
                'C3750' in system_info['system_sw_version'] or\
                'IOS-XE' in system_info['system_sw_version'] or\
                'C2960' in system_info['system_sw_version']:
            cam_lines = cam_buff.split('----    -----------       --------    -----')[1].split('\r\n')
        else:
            cam_lines = cam_buff.split('------+----------------+--------+-----+----------+--------------------------')[1].split('\r\n')

    cam_lines.pop(-1)

    ssh_session.sendline(shared.IOS_SHOW_CDP_DETAIL)
    ssh_session.expect([TIMEOUT, prompt])
    cdp_buff = ssh_session.before
    cdp_data = str(cdp_buff).split('-------------------------')

    shared.kill_ssh_session(ssh_session)
    addr_line_split = system_ip_address_buff.split(
        'Interface                  IP-Address      OK? Method Status                Protocol')
    if len(addr_line_split) == 1:
        addr_line_split = system_ip_address_buff.split(
            'Interface              IP-Address      OK? Method Status                Protocol')
    addrs_nl_split = addr_line_split[1].split('\r\n')

    addrs_nl_split.pop(-1)

    for line in addrs_nl_split:
        if line:
            addrs_line = line.split()
            if addrs_line:
                if len(addrs_line) == 3:
                    status = addrs_line[2]
                else:
                    status = '%s/%s' % (addrs_line[4],
                                        addrs_line[5])
                d = {'system_ip_address': addrs_line[1],
                     'name': addrs_line[0],
                     'status': status
                     }
                if d not in system_ip_list:
                    system_ip_list.append(d)

    local_subnets = local_subnets_buff.split('show ip route connected | in C')
    local_subnets_lines = local_subnets[1].split('\r\n')
    local_subnets_lines.pop(-1)

    for subnet_line in local_subnets_lines:
        if subnet_line:
            subnet_split = subnet_line.split()
            if subnet_split[0] != '^':
                if shared.is_subnet(subnet_split[1]):
                    subnet = subnet_split[1]
                    source_int = subnet_split[-1]
                    local_subnet_dict = {'subnet': subnet,
                                         'source_interface': source_int}
                    if local_subnet_dict not in subnet_list:
                        subnet_list.append(local_subnet_dict)

    cdp_list = shared.get_cdp_list(cdp_data)

    for cam_line in cam_lines:
        if cam_line:
            cam_line = cam_line.split()
            if cam_line:
                if cam_line[0] == '*':
                    cam_line = cam_line[1:]
                if cam_line[0]:
                    if cam_line[0] == '---':
                        vlan_id = 0
                    else:
                        try:
                            vlan_id = int(cam_line[0])
                        except ValueError:
                            continue
                    mac_vendor = shared.lookup_mac_vendor(cam_line[1].replace('.', ''))
                    mac_addr_dict = {'mac_address': cam_line[1],
                                     'mac_vendor': mac_vendor,
                                     'type': cam_line[2],
                                     'port': cam_line[-1],
                                     'vlan':  vlan_id}
                    if mac_addr_dict not in mac_list:
                        mac_list.append(mac_addr_dict)

    for arp_line in arp_lines:
        if arp_line:
            line = arp_line.split()
            for x in mac_list:
                if x['mac_address'] == line[3]:

                    host_dict = {'host_address': line[1],
                                 'mac_address': line[3],
                                 'adjacency_interface': line[-1],
                                 'mac_vendor': x['mac_vendor'],
                                 'type': x['type'],
                                 'port': x['port'],
                                 'vlan': x['vlan']}

                    if host_dict not in host_list:
                        host_list.append(host_dict)

    # todo: add ios nat
    # data['nat_list'] = nat_list
    data['system_ip_list'] = system_ip_list
    data['system_info'] = system_info
    data['subnet_list'] = subnet_list
    data['host_list'] = host_list
    data['discovery_list'] = cdp_list

    return data
