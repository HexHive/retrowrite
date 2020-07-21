#!/usr/bin/python3
import argparse
import json
import os

def main():
    parser = argparse.ArgumentParser(
            description='Generate a configuration file for syzkaller')

    parser.add_argument('--workdir', help='workdir for syzkaller', required=True)
    parser.add_argument('--kernel', help='path to the kernel directory', required=True)
    parser.add_argument('--initramfs', help='path to the initramfs', required=True)
    parser.add_argument('--image', help='path to the disk image', required=True)
    parser.add_argument('--sshkey', help='path to the VM\'s SSH key', required=True)
    parser.add_argument('--syzkaller', help='path to syzkaller', required=True)
    parser.add_argument('--vms', help='number of VMs', type=int, default=8)
    parser.add_argument('--cpus', help='CPUs per VM', type=int, default=2)
    parser.add_argument('--mem', help='memory per VM', type=int, default=2048)
    parser.add_argument('config', help='path to the original config')
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    config['reproduce'] = False

    config['vm']['count'] = args.vms
    config['vm']['kernel'] = os.path.join(args.kernel, 'arch', 'x86', 'boot',
            'bzImage')
    config['vm']['initrd'] = args.initramfs
    config['vm']['cpu'] = args.cpus
    config['vm']['mem'] = args.mem

    config['workdir'] = args.workdir
    config['kernel_obj'] = args.kernel
    config['image'] = args.image
    config['sshkey'] = args.sshkey
    config['syzkaller'] = args.syzkaller

    print(json.dumps(config, indent=4))

if __name__ == '__main__':
    main()

