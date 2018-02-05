from netrecon import shared
from pexpect import TIMEOUT
from ipaddress import ip_address
from re import search, sub
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

    if ssh_session == 99:
        print('ERROR: ssh session to %s timed out' % system_address)
        return 99
    if ssh_session == 98:
        print('ERROR: %s refused the ssh session' % system_address)
        return 98
    if ssh_session == 97:
        print('ERROR: system has a bad ssh key for %s' % system_address)
        return 97
    if ssh_session == 96:
        print('VULNERABLE: %s is using ssh v1' % system_address)
        return 96
    if ssh_session == 95:
        print('ERROR: password denied for %s' % system_address)
        return 95
    if ssh_session == 94:
        print('ERROR: permission denied for %s' % system_address)
        return 94
    if ssh_session == 93:
        print('ERROR: EOF for %s' % system_address)
        return 93
    if ssh_session == 1:
        print('ERROR: just did not connect to %s' % system_address)
        return 1
    infrastructure_os, ssh_session, prompt = shared.discover_os(ssh_session, prompt, password)
    try:
        if infrastructure_os['os']:
            if infrastructure_os['os'] == 'panos':
                data = get_panos_hosts(ssh_session, prompt)
            elif infrastructure_os['os'] == 'ios':
                data = get_ios_hosts(ssh_session, prompt)
            elif infrastructure_os['os'] == 'asaos':
                data = get_asa_hosts(ssh_session, prompt)
            elif infrastructure_os['os'] == 'linux':
                data = infrastructure_os['os']
                shared.kill_ssh_session(ssh_session)
    except KeyError as e:
        print('ERROR: %s' % str(e))
    return data


def get_panos_hosts(ssh_session, prompt):
    data = dict()
    local_host_dict_list = list()
    local_subnets_dict_list = list()
    ssh_session.expect([TIMEOUT, prompt])
    ssh_session.sendline(shared.PAN_SHOW_ARP)
    ssh_session.expect([TIMEOUT, prompt])
    arp_buff = ssh_session.before
    arp = arp_buff.split('--------------------------------------------------------------------------------')
    shared.kill_ssh_session(ssh_session)
    split_arp = arp[1].split('\r\n')
    for e in split_arp:
        if e != '':
            entry = e.rstrip().split()
            if len(entry) == 6:
                if entry[4] == 'c':
                    ip_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', entry[1])
                    mac_addr = entry[2].replace(':', '')
                    mac_vendor = shared.lookup_mac_vendor(mac_addr)
                    if ip_addrs:
                        if ip_address(ip_addrs.group(0)).is_private:
                            host_dict = {'interface': entry[0],
                                         'ip_addr': ip_addrs.group(0),
                                         'hw_addr': mac_addr,
                                         'port': entry[3],
                                         'mac_vendor': mac_vendor
                                         }
                            local_host_dict_list.append(host_dict)
    data['local_host_dict_list'] = local_host_dict_list
    return data


def get_ios_hosts(ssh_session, prompt):
    data = dict()
    secondary_addrs_dict_list = list()
    local_host_dict_list = list()
    local_subnets_dict_list = list()
    mac_dict_list = list()
    discovery_dict_list = list()
    adjacency_addrs_list = list()
    license_level = None
    system_serial_number = None
    model_number = None

    ssh_session.sendline(shared.IOS_SWITCH_SHOW_SERIALNUM)
    ssh_session.expect([TIMEOUT, prompt])
    ios_switch_sn = ssh_session.before

    ssh_session.sendline(shared.IOS_SWITCH_SHOW_MODEL)
    ssh_session.expect([TIMEOUT, prompt])
    ios_switch_model = ssh_session.before

    ssh_session.sendline(shared.IOS_RTR_SHOW_SERIALNUM)
    ssh_session.expect([TIMEOUT, prompt])
    ios_rtr_sn = ssh_session.before

    ssh_session.sendline(shared.IOS_RTR_SHOW_MODEL)
    ssh_session.expect([TIMEOUT, prompt])
    ios_rtr_model = ssh_session.before

    ssh_session.sendline(shared.IOS_LAST_RESORT_SHOW_MODEL)
    ssh_session.expect([TIMEOUT, prompt])
    ios_last_resort_model = ssh_session.before

    ssh_session.sendline(shared.IOS_SHOW_LICS)
    ssh_session.expect([TIMEOUT, prompt])
    ios_lics_model = ssh_session.before

    ssh_session.sendline(shared.IOS_SHOWIPINTBR)
    ssh_session.expect([TIMEOUT, prompt])
    secondary_addrs_buff = ssh_session.before
    sec_addr_lines = secondary_addrs_buff.split('\r\n')

    ssh_session.sendline(shared.IOS_SHOW_ADJACENCY)
    ssh_session.expect([TIMEOUT, prompt])
    local_hosts_buff = ssh_session.before
    local_hosts_lines = local_hosts_buff.split('\r\n')

    ssh_session.sendline(shared.IOS_SHOW_LOCAL_CONNECTIONS)
    ssh_session.expect([TIMEOUT, prompt])
    local_subnets_buff = ssh_session.before
    local_subnets_lines = local_subnets_buff.split('\r\n')

    ssh_session.sendline(shared.IOS_SHOW_ARP)
    ssh_session.expect([TIMEOUT, prompt])
    arp_buff = ssh_session.before
    arp_lines = arp_buff.split('\r\n')

    ssh_session.sendline(shared.IOS_SHOW_CAM)
    ssh_session.expect([TIMEOUT, prompt])
    cam_buff = ssh_session.before
    cam_lines = cam_buff.split('\r\n')

    ssh_session.sendline(shared.IOS_SHOW_CDP_DETAIL)
    ssh_session.expect([TIMEOUT, prompt])
    cdp_buff = ssh_session.before
    data_list = str(cdp_buff).split('-------------------------')

    shared.kill_ssh_session(ssh_session)
    rsi_output = '%s%s%s%s%s%s' % (ios_switch_sn,
                                   ios_switch_model,
                                   ios_rtr_sn,
                                   ios_rtr_model,
                                   ios_last_resort_model,
                                   ios_lics_model)

    rsinfo_lines = rsi_output.split('\r\n')

    for new_line in rsinfo_lines:
        lic_level_match = search(r'^License\s+Level\s*:\s+([^\s]+)', new_line)

        if lic_level_match:
            license_level = lic_level_match.group(1)

        switch_model_num_match = search(r'^Model\s+number\s*:\s+([^\s]+)', new_line)

        if switch_model_num_match:
            model_number = switch_model_num_match.group(1)
        rtr_model_num_match = search(r'(^\*[0-9]+\s+)([A-Za-z0-9]+)', new_line)

        if rtr_model_num_match:
            model_number = rtr_model_num_match.group(2)

        system_sn_match = search(r'^System\s+serial\s+number\s*:\s+([^\s]+)', new_line)
        sn_match = search(r'^Serial\s+Number\s*:\s+([^\s]+)', new_line)

        if system_sn_match:
            system_serial_number = system_sn_match.group(1)
        elif sn_match:
            system_serial_number = sn_match.group(1)

        router_sn_match = search(r'(^Processor\s+board\s+ID\s+)(\S+)', new_line)

        if router_sn_match:
            system_serial_number = router_sn_match.group(2)

        # last resort model number search
        if model_number is None:

            for l in rsinfo_lines:
                ws_model_num_match = search(r'(WS-\S+)', l)

                if ws_model_num_match:
                    model_number = ws_model_num_match.group(0)
                    break

        if license_level is None:
            license_level = 'unknown'

        rsinfrastructure = {'rsi_os_version': '',
                            'rsi_license_level': license_level,
                            'rsi_system_serial_number': system_serial_number,
                            'rsi_model_number': model_number,
                            'rsi_timestamp': int(time.time())}

        for sec_addr_line in sec_addr_lines:
            rsaddr = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                            r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                            r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                            r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', sec_addr_line)
            if rsaddr:
                d = {'rsaddr': str(rsaddr.group(0))}
                if d not in secondary_addrs_dict_list:
                    secondary_addrs_dict_list.append(d)
        if local_hosts_lines:
            for local_hosts_line in local_hosts_lines:
                ip_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                  r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                  r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                  r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', local_hosts_line)

                interface = search(r'(^\S+[ \t]{2,})(\S+)', local_hosts_line)

                if interface and ip_addrs:
                    matched_line = interface.group(0).split(' ')
                    interface_adjacency = matched_line[-1]
                    adj_dict = {str(ip_addrs.group(0)): str(interface_adjacency)}
                    if adj_dict not in adjacency_addrs_list:
                        adjacency_addrs_list.append(adj_dict)

        for subnet_line in local_subnets_lines:
            match = search(r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d+)', subnet_line)
            direct_connect_match = search(r'(directly connected,)(\s+)(\S+)', subnet_line)

            if match and direct_connect_match:
                local_subnet_dict = {'subnet': match.group(0),
                                     'source_int': direct_connect_match.group(3)}
                if local_subnet_dict not in local_subnets_dict_list:
                    local_subnets_dict_list.append(local_subnet_dict)

        for arp_line in arp_lines:
            ip_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                              r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                              r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                              r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', arp_line)

            # and search each line for mac addresses
            mac_addrs = search(r'(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})', arp_line)

            if ip_addrs and mac_addrs:

                for addr in adjacency_addrs_list:
                    if ip_addrs.group(0) in addr:
                        mac_addr = mac_addrs.group(0).replace('.', '')
                        mac_vendor = shared.lookup_mac_vendor(mac_addr)
                        host_dict = {'local_host_ip_addr': ip_addrs.group(0),
                                     'mac_addr': mac_addr,
                                     'local_host_adjacency_int': addr[ip_addrs.group(0)],
                                     'mac_vendor': mac_vendor}
                        if host_dict not in local_host_dict_list:
                            local_host_dict_list.append(host_dict)

        if cam_lines:
            for cam_line in cam_lines:
                mac_addrs = search(r'(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})', cam_line)

                if mac_addrs:
                    mac_addrs_line_split = cam_line.strip('*').split(' ')
                    mac_addrs_line_split = list(filter(None, mac_addrs_line_split))

                    if mac_addrs_line_split[0] == '---':
                        vlan_id = '0'
                    else:
                        vlan_id = mac_addrs_line_split[0]

                    mac_addr_dict = {'mac_table_mac_addr': mac_addrs_line_split[1],
                                     'mac_table_type': mac_addrs_line_split[2],
                                     'mac_table_port': mac_addrs_line_split[3].strip('\r\n'),
                                     'mac_table_vlan': int(vlan_id)}
                    if mac_addr_dict not in mac_dict_list:
                        mac_dict_list.append(mac_addr_dict)

        if data_list:
            for element in data_list:
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
                reg_entry_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                         r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                         r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                         r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', element)

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
                    if discovery_dictionary not in discovery_dict_list:
                        discovery_dict_list.append(discovery_dictionary)
    data['local_host_dict_list'] = local_host_dict_list
    return data


def get_asa_hosts(ssh_session, prompt):
    data = dict()
    local_host_dict_list = list()
    local_subnets_dict_list = list()

    ssh_session.sendline(shared.ASA_SHOW_SERIALNUM)
    ssh_session.expect([TIMEOUT, prompt])
    time.sleep(.1)
    asa_sn = ssh_session.before

    ssh_session.sendline(shared.ASA_SHOW_MODEL)
    ssh_session.expect([TIMEOUT, prompt])
    time.sleep(.1)
    asa_model = ssh_session.before

    ssh_session.sendline(shared.ASA_SHOW_IP)
    ssh_session.expect([TIMEOUT, prompt])
    time.sleep(.1)
    asa_addrs_buff = ssh_session.before
    sec_addr_lines = asa_addrs_buff.split('\r\n')

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

    shared.kill_ssh_session(ssh_session)

    rsi_output = '%s%s' % (asa_sn,
                           asa_model)

    for subnet_line in local_subnets_lines:
        subnet_line_list = list(filter(None, subnet_line.split(' ')))
        try:
            ip_addr = subnet_line_list[1]
            mask = subnet_line_list[2]
            interface = subnet_line_list[-1:][0]
        except IndexError:
            continue
        ip_addr_match = search(r'((?:[0-9]{1,3}\.){3}[0-9]{1,3})', ip_addr)
        if ip_addr_match:
            mask_match = search(r'((?:[0-9]{1,3}\.){3}[0-9]{1,3})', mask)
            if mask_match:
                local_subnet_dict = {'subnet': '%s/%s' % (ip_addr, IPAddress(mask).netmask_bits()),
                                     'source_int': interface}
                if local_subnet_dict not in local_subnets_dict_list:
                    local_subnets_dict_list.append(local_subnet_dict)
    for a in arp_lines:

        arp_split = a.split(' ')
        try:
            mac_addr = arp_split[2].replace('.', '')
        except IndexError:
            continue
        mac_vendor = shared.lookup_mac_vendor(mac_addr)

        host_dict = {'ip_addr': arp_split[1],
                     'mac_addr': mac_addr,
                     'local_host_adjacency_int': arp_split[0],
                     'mac_vendor': mac_vendor}
        if host_dict not in local_host_dict_list:
            local_host_dict_list.append(host_dict)
    data['local_host_dict_list'] = local_host_dict_list
    return data
