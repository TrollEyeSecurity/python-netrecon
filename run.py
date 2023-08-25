#!/usr/bin/env python3

from netrecon import recon
import json
import os
import argparse


def main():
    parser = argparse.ArgumentParser(description='Arguments for running NetRecon')
    parser.add_argument('--write_output', action='store_true', default=False)
    parser.add_argument('--host', type=str, action='store')

    args = parser.parse_args()

    if not args.host:
        host = os.getenv('NETRECON_HOST')
    else:
        host = args.host

    username = os.getenv('NETRECON_USERNAME')
    password = os.environ.get('NETRECON_PASSWORD')
    recon_output = recon.host_discovery(host, username, password)

    if recon_output == 99:
        recon_output = {'error': 99, 'msg': '%s timed out' % host}
    # 98 = connection refused
    elif recon_output == 98:
        recon_output = {'error': 98, 'msg': '%s connection refused' % host}
    # 97 = bad ssh key
    elif recon_output == 97:
        recon_output = {'error': 97, 'msg': '%s bad ssh key' % host}
    # 96 = using ssh v1
    elif recon_output == 96:
        recon_output = {'error': 96, 'msg': '%s using ssh v1' % host}
    # 95 = password denied
    elif recon_output == 95:
        recon_output = {'error': 95, 'msg': '%s password denied' % host}
    # 94 = permission denied
    elif recon_output == 94:
        recon_output = {'error': 94, 'msg': '%s permission denied' % host}
    # 93 = EOF
    elif recon_output == 93:
        recon_output = {'error': 93, 'msg': '%s EOF' % host}
    # 92 = network unreachable
    elif recon_output == 92:
        recon_output = {'error': 92, 'msg': '%s network unreachable' % host}
    # 91 = no route to host
    elif recon_output == 91:
        recon_output = {'error': 91, 'msg': '%s no route to host' % host}
    # 1 = could not connect
    elif recon_output == 1:
        recon_output = {'error': 1, 'msg': '%s could not connect' % host}
    if args.write_output:
        if not recon_output:
            print('no output from %s' % host)
            exit()
        with open("data/%s.json" % host, "w") as data_file:
            json.dump(recon_output, data_file, indent=4)

    else:
        print(json.dumps(recon_output))


if __name__ == '__main__':
    try:
        main()
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print('Crtl+C Pressed. Shutting down.')
