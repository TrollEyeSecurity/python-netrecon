from netrecon import shared
from pexpect import TIMEOUT, exceptions as pexceptions
from ipaddress import ip_address


class HostDiscovery(object):
    def __init__(self, system_address, username):
        self.system_address = system_address
        self.username = username

        self.run()

    def run(self):
        local_host_dict_list = list()
        ssh_session, prompt = shared.get_ssh_session(self.system_address, self.username)
        # print('got session with %s' % self.system_address)
        # 99 = timed out
        # 98 = connection refused
        # 97 = bad ssh key
        # 96 = using ssh v1
        # 95 = password denied
        # 94 = permission denied

        if ssh_session == 99:
            print('ERROR: ssh session to %s timed out' % self.system_address)
            return 99
        if ssh_session == 98:
            print('ERROR: %s refused the ssh session' % self.system_address)
            return 98
        if ssh_session == 97:
            print('ERROR: system has a bad ssh key for %s' % self.system_address)
            return 97
        if ssh_session == 96:
            print('VULNERABLE: %s is using ssh v1' % self.system_address)
            return 96
        if ssh_session == 95:
            print('ERROR: password denied for %s' % self.system_address)
            return 95
        if ssh_session == 94:
            print('ERROR: permission denied for %s' % self.system_address)
            return 94
        if ssh_session == 93:
            print('ERROR: EOF for %s' % self.system_address)
            return 93
        if ssh_session == 1:
            print('ERROR: just did not connect to %s' % self.system_address)
            return 1
        # see how the session responds
        infrastructure_os, ssh_session, prompt = shared.discover_os(ssh_session, prompt)
        try:
            if infrastructure_os['os']:
                if infrastructure_os['os'] == 'panos':
                    print('%s is a %s system' % (self.system_address, infrastructure_os['os']))
                if infrastructure_os['os'] == 'ios':
                    print('%s is a %s system' % (self.system_address, infrastructure_os['os']))
                if infrastructure_os['os'] == 'asaos':
                    print('%s is a %s system' % (self.system_address, infrastructure_os['os']))
                if infrastructure_os['os'] == 'linux':
                    print('%s is a %s system' % (self.system_address, infrastructure_os['os']))
        except KeyError as e:
            print('ERROR: %s' % str(e))
        try:
            ssh_session.close()
        except pexceptions.ExceptionPexpect as e1:
            print('INFO: %s for %s' % (str(e1), self.system_address))
            try:
                ssh_session.close()
            except pexceptions.ExceptionPexpect as e2:
                print('ERROR: %s for %s' % (str(e2), self.system_address))
                return 1
