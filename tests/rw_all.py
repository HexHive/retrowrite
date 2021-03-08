import argparse
import json
import subprocess
import os
from multiprocessing import Pool


def do_test(cmd):
    print("[!] Running on {}".format(cmd))
    try:
        subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError:
        print("[x] Failed {}".format(cmd))


def do_tests(tests, filter, args, outdir):
    assert not (args.ddbg and args.parallel)
    pool = Pool()
    for test in tests:
        if not filter(test):
            continue

        path = test["path"]
        binp = os.path.join(path, test["name"])
        outp = os.path.join(outdir, test["name"] + ".s")

        if args.ddbg:
            outp = os.path.join(outdir, test["name"] + "_asan")
            cmd = "python -m debug.ddbg {} {}".format(binp, outp)
        elif args.asan:
            outp = os.path.join(outdir, test["name"] + "_asan")
            cmd = "retrowrite --asan {} {}".format(binp, outp)
        else:
            cmd = "python -m librw.rw {} {}".format(binp, outp)

        if args.parallel:
            pool.apply_async(do_test, args=(cmd, ))
        else:
            do_test(cmd)

    pool.close()
    pool.join()


if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument("test_file", type=str, help="JSON file containing tests")
    argp.add_argument(
        "--targets",
        type=str,
        help="Only test build target, comma separated string of names")
    argp.add_argument(
        "--asan",
        action='store_true',
        help="Instrument with asan")
    argp.add_argument(
        "--ddbg",
        action='store_true',
        help="Do delta debugging")
    argp.add_argument(
        "--parallel",
        action='store_true',
        help="Do multiple tests in parallel")

    args = argp.parse_args()

    filter = lambda x: True
    if args.targets:
        filter = lambda x: x["name"] in args.targets.split(",")

    args.testfile = os.path.abspath(args.test_file)
    outdir = os.path.dirname(args.test_file)

    with open(args.test_file) as tfd:
        do_tests(json.load(tfd), filter, args, outdir)
