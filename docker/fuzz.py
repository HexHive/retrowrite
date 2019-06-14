#!/usr/bin/env python3

import argparse
import yaml
import os
import subprocess
import json
import greenstalk
import copy
import time
import datetime

from string import Template


def do_fuzz(args):
    with open(args.fuzz_config, 'r') as fd:
        config = yaml.load(fd)

    host, port = config['vars']['queue'].split(':')

    queue = greenstalk.Client(
        host=host, port=int(port), use='jobs', watch=['jobs'])

    while True:
        print(
            "=================================================================="
        )
        job = queue.reserve()
        queue.bury(job)
        current = json.loads(job.body)
        print(job.body)
        # Setup
        subprocess.check_call("mkdir -p " + current["workdir"], shell=True)
        subprocess.check_call(
            "unzip %s -d %s/fuzz-in" % (current['seed'], current['workdir']),
            shell=True)
        # Fuzz
        per_proc_timeout = current['timeout'] / current['jobs']
        jobids = list()
        for i in range(current['jobs']):
            indir = os.path.join(current["workdir"], "fuzz-in")
            outdir = os.path.join(current["workdir"], "fuzz-out")
            if i == 0:
                afl = Template(current["fuzz_cmd"]).substitute(
                    fuzz_in=indir, fuzz_out=outdir)
                afl = afl + " -m 200 -M fuzzer%d" % (i)
            else:
                afl = Template(current["fuzz_cmd"]).substitute(
                    fuzz_in=indir, fuzz_out=outdir)
                afl = afl + " -m 200 -S fuzzer%d" % (i)

            # Set AFL stuff correctly
            subprocess.check_call(
                "echo core >/proc/sys/kernel/core_pattern;" +
                "cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor",
                shell=True)

            pid = subprocess.Popen(
                "screen -d -m timeout %d " % (per_proc_timeout) + afl + " -- " +
                current["cmd"],
                shell=True)

            jobids.append(pid)

        print(datetime.datetime.now())
        print("Processing: " + str(current) +
              " Sleep: %ds" % (per_proc_timeout + 60.0))
        time.sleep(60.0)

        # Check if the fuzzer is running correctly!
        afl_procs = subprocess.check_output("pgrep afl*", shell=True).split()
        if len(afl_procs) < current['jobs']:
            print("[X] Failed to verify running fuzzer, aborting!")
            subprocess.Popen("pkill screen*", shell=True)
            time.sleep(5.0)
            continue

        print("[I] Fuzzer running OK! Time to rest.")
        time.sleep(per_proc_timeout + 60.0)

        # Save
        tarf = os.path.join(
            config['vars']['save'], "%s-%s-trial-%d.tar.gz" %
            (current['key'], current['suffix'], current['trial']))

        subprocess.check_call(
            "tar -cvf %s %s" % (tarf, current['workdir']), shell=True)

        # Cleanup
        queue.delete(job)

    queue.close()


def do_load(args):
    with open(args.fuzz_config, 'r') as fd:
        config = yaml.load(fd)

    with open(args.fuzz_file, 'r') as fd:
        fuzzd = yaml.load(fd)

    host, port = config['vars']['queue'].split(':')
    queue = greenstalk.Client(
        host=host, port=int(port), use='jobs', watch=['jobs'])

    for target in fuzzd['fuzz_targets']:
        props = copy.copy(fuzzd[target])
        meta = config[props['key']]
        for i in range(1, config['vars']['trials'] + 1):
            props['trial'] = i

            props['timeout'] = config['vars']['time']
            if props['timeout'].endswith('h'):
                props['timeout'] = "%sm" % (int(props['timeout'][:-1]) * 60)

            if props['timeout'].endswith('m'):
                props['timeout'] = int(props['timeout'][:-1]) * 60
            elif props['timeout'].endswith('s'):
                props['timeout'] = int(props['timeout'][:-1])

            props['jobs'] = config['vars']['jobs']
            props['ncores'] = config['vars']['ncores']
            props['cmd'] = meta['cmd'].replace("bin", props['path'])
            props['seed'] = os.path.join(config['vars']['seeds'], meta['seed'])
            props['workdir'] = os.path.join(config['vars']['workdir'], target,
                                            str(i))

            queue.put(json.dumps(props))


if __name__ == '__main__':
    argp = argparse.ArgumentParser()

    argp.add_argument(
        "--load",
        action='store_true',
        help="Load fuzz targets to a queue",
    )

    argp.add_argument(
        "--fuzz",
        action='store_true',
        help="Start fuzzing runs from queue",
    )

    argp.add_argument("fuzz_config", help="YAML Fuzzer configuration file")

    argp.add_argument(
        "fuzz_file", help="YAML configuration file for fuzz targets")

    args = argp.parse_args()

    assert args.fuzz or args.load

    if args.fuzz:
        do_fuzz(args)
    else:
        do_load(args)
