#!/usr/bin/env python3

import argparse
import yaml
import os
import subprocess

from string import Template


def parse_config(config):
    global_vars = dict()
    build_scripts = list()
    fuzzdict = dict()
    fuzzdict['fuzz_targets'] = list()

    with open(config, 'r') as fd:
        configd = yaml.load(fd)

    for var, value in configd['vars'].items():
        global_vars[var] = value

    for target in configd['targets']:
        commands = list()

        # Setup
        bt = configd[target]
        clonecmd = bt['clone']

        # Setup save directories
        for sysname in configd['systems']:
            savedir = os.path.join(global_vars['save'], target, sysname)
            commands.append("mkdir -p " + savedir)

        commands.append("\n")
        commands.append(clonecmd)
        commands.append("cd %s\n" % (target))
        commands.extend(bt['setup'])

        for sysname in configd['systems']:
            target_sysname_tuple = target + "-" + configd[sysname]['suffix']
            fuzzdict['fuzz_targets'].append(target_sysname_tuple)
            fuzzdict[target_sysname_tuple] = {
                'key': target,
                'suffix': configd[sysname]['suffix']
            }

            local_vars = dict()
            for var, value in configd[sysname]['vars'].items():
                local_vars[var] = value
            flagstr = []
            for bf, bfvalue in bt['build_flags'].items():
                if bfvalue in global_vars:
                    flagstr.append("%s=%s" % (bf, global_vars[bfvalue]))
                elif bfvalue in local_vars:
                    flagstr.append("%s=%s" % (bf, local_vars[bfvalue]))
                else:
                    flagstr.append("%s=%s" % (bf, bfvalue))

            envstr = []
            for bf, bfvalue in bt['env'].items():
                if bfvalue in global_vars:
                    envstr.append("%s=%s" % (bf, global_vars[bfvalue]))
                elif bfvalue in local_vars:
                    envstr.append("%s=%s" % (bf, local_vars[bfvalue]))
                else:
                    envstr.append("%s=%s" % (bf, bfvalue))

            buildsteps = bt['build']
            build_single = [
                "%s %s %s" % (' '.join(envstr), buildsteps[0],
                              ' '.join(flagstr))
            ]

            build_single.extend(buildsteps[1:])

            for binary in bt['binaries']:
                bpath = os.path.join(global_vars['install'], binary)
                bname = os.path.basename(binary)
                spath = os.path.join(
                    global_vars['save'], target, sysname,
                    "%s-%s" % (bname, configd[sysname]['suffix']))

                build_single.append('cp %s %s' % (bpath, spath))

                if 'post' in configd[sysname]:
                    for key in configd[sysname]['post']:
                        post_target_sysname_tuple = target + '-' + key
                        fuzzdict['fuzz_targets'].append(
                                post_target_sysname_tuple
                        )

                        fuzzdict[post_target_sysname_tuple] = {
                            'key': target,
                            'suffix': key,
                        }

                        postsys = configd[key]
                        binbase = os.path.basename(spath)
                        postsave = os.path.join(global_vars['save'], target,
                                                key)

                        build_single.append("mkdir -p " + postsave)

                        postsave = os.path.join(
                            postsave, "%s-%s" % (bname, postsys['suffix']))

                        if 'target-flags' in postsys:
                            postflags = postsys['target-flags'][target]
                        else:
                            postflags = ""

                        for command in postsys['cmd']:
                            command = Template(command).substitute(
                                dict(target_lib=binbase,
                                     target_save=postsave,
                                     target_in=spath,
                                     target_flags=postflags))
                            build_single.append(command)

                        fuzzdict[post_target_sysname_tuple]['path'] = postsave
                        fuzzdict[post_target_sysname_tuple]['fuzz_cmd'] = postsys['fuzz_cmd']
                        build_single.append("")

                fuzzdict[target_sysname_tuple]['path'] = spath
                fuzzdict[target_sysname_tuple]['fuzz_cmd'] = configd[sysname]['fuzz_cmd']

            commands.append('\n'.join(build_single))
            if 'cleanup' in bt:
                commands.append(bt['cleanup'])
            else:
                commands.append("make clean\n")

        print("[*] Writing out %s" % (target))
        with open("build-%s.sh" % (target), 'w') as fd:
            fd.write("#!/bin/bash\n\n")
            fd.write("\n".join(commands))

        build_scripts.append("build-%s.sh" % (target))

    with open("fuzz.yaml", 'w') as fd:
        fd.write(yaml.dump(fuzzdict, default_flow_style=False))

    with open("build-all.sh", 'w') as fd:
        fd.write("#!/bin/bash\n\n")
        fd.write("\n".join(["./" + x for x in build_scripts]))

    subprocess.check_call("chmod +x build-all.sh", shell=True)
    for file in build_scripts:
        subprocess.check_call("chmod +x " + file, shell=True)


if __name__ == '__main__':
    argp = argparse.ArgumentParser()
    argp.add_argument(
        "config", help="YAML configuration file to use for build.")
    argp.add_argument("--fuzz-file", help="Path to save fuzz-file to.")

    args = argp.parse_args()
    config = parse_config(args.config)
