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
        recon_output = '%s timed out' % host
        print('%s timed out' % host)
    # 98 = connection refused
    elif recon_output == 98:
        recon_output = '%s connection refused' % host
        print('%s connection refused' % host)
    # 97 = bad ssh key
    elif recon_output == 97:
        recon_output = '%s bad ssh key' % host
        print('%s bad ssh key' % host)
    # 96 = using ssh v1
    elif recon_output == 96:
        recon_output = '%s using ssh v1' % host
        print('%s using ssh v1' % host)
    # 95 = password denied
    elif recon_output == 95:
        recon_output = '%s password denied' % host
        print('%s password denied' % host)
    # 94 = permission denied
    elif recon_output == 94:
        recon_output = '%s permission denied' % host
        print('%s permission denied' % host)
    # 93 = EOF
    elif recon_output == 93:
        recon_output = '%s EOF' % host
        print('%s EOF' % host)
    # 92 = network unreachable
    elif recon_output == 92:
        recon_output = '%s network unreachable' % host
        print('%s network unreachable' % host)
    # 91 = no route to host
    elif recon_output == 91:
        recon_output = '%s no route to host' % host
        print('%s no route to host' % host)
    # 1 = could not connect
    elif recon_output == 1:
        recon_output = '%s could not connect' % host
        print('%s could not connect' % host)
    else:
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
