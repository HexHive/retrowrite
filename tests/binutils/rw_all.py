import argparse
import json
import subprocess
import os


def do_test(tests, filter):
    for test in tests:
        if not filter(test):
            continue

        path = test["path"]
        binp = os.path.join(path, test["name"])
        outp = os.path.join("./binutils/", test["name"] + ".s")

        try:
            subprocess.check_call(
                "python -m librw.rw {} {}".format(binp, outp), shell=True)
        except subprocess.CalledProcessError:
            print("[x] Failed: {}".format(test["name"]))


if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument("test_file", type=str, help="JSON file containing tests")
    argp.add_argument(
        "--targets",
        type=str,
        help="Only test build target, comma separated string of names")

    args = argp.parse_args()

    filter = lambda x: True
    if args.targets:
        filter = lambda x: x["name"] in args.targets.split(",")

    with open(args.test_file) as tfd:
        do_test(json.load(tfd), filter)
