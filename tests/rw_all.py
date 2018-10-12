import argparse
import json
import subprocess
import os


def do_test(tests, filter, asan, outdir):
    for test in tests:
        if not filter(test):
            continue

        path = test["path"]
        binp = os.path.join(path, test["name"])
        outp = os.path.join(outdir, test["name"] + ".s")

        print("[!] Running on {}".format(test["name"]))

        try:
            subprocess.check_call(
                "python -m librw.rw {} {}".format(binp, outp), shell=True)
        except subprocess.CalledProcessError:
            print("[x] Failed: {}".format(test["name"]))

        if asan:
            try:
                outp = os.path.join(outdir, test["name"] + "_asan")
                subprocess.check_call(
                    "python -m rwtools.asan.asantool {} {}".format(binp, outp), shell=True)
            except subprocess.CalledProcessError:
                print("[x] Failed ASAN: {}".format(test["name"]))


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

    args = argp.parse_args()

    filter = lambda x: True
    if args.targets:
        filter = lambda x: x["name"] in args.targets.split(",")

    args.testfile = os.path.abspath(args.test_file)
    outdir = os.path.dirname(args.test_file)

    with open(args.test_file) as tfd:
        do_test(json.load(tfd), filter, args.asan, outdir)
