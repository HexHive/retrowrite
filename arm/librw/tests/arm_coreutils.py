from capstone import *
from keystone import *
from arm.librw.util.logging import *
import subprocess
import sys
import os

coreutils_path = os.path.expanduser("~/coreutils/src/")
test_bins = [
        ("ls",        [ "/etc", "/etc -la", "/home"]),
        ("od",        [ "/etc/passwd"]),
        ("head",      [ "/etc/passwd"]),
        ("tail",      [ "/etc/passwd", "/etc/passwd -n 2"]),
        ("cat",       [ "/etc/passwd"]),
        ("uname",     [ "", "-a"]),
        ("seq",       [ "1 10", "1 2 100"]),
        ("tr",        [ "abc def < /etc/passwd"]),
        ("env",       [ "", "-0"]),
        ("base64",    [ "/etc/passwd", "/etc/bash.bashrc"]),
        ("sha256sum", [ "/etc/passwd", "/etc/passwd --tag"]),
        ("getlimits", [ "", "--version"]),
        ("fmt",       [ "/etc/passwd -w 10", "/etc/bash.bashrc"]),
        ("wc",        [ "/etc/passwd", "-L /etc/bash.bashrc"]),
        ("nl",        [ "/etc/passwd", "/etc/passwd -b psy"]),
        ]

def cmd(text):
    try:
        return subprocess.check_output(text, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        return e.output

def check_arch():
    res = cmd("lscpu")
    if b"aarch64" not in res.split():
        critical("Those tests can only be run on an ARM 64 architecture - exiting")
        exit(1)

def check_files():
    global coreutils_path
    if "COREUTILS_PATH" in os.environ:
        coreutils_path = os.environ["COREUTILS_PATH"]
    if not os.path.isdir(coreutils_path):
        critical(f"Coreutils not found in {coreutils_path}. Either install them there\
                  or set environment variable COREUTILS_PATH to the directory containing the binaries.")
        exit(1)
    for binary in list(map(lambda x: x[0], test_bins)):
        if not os.path.exists(coreutils_path + binary):
            critical(f"Binary {binary} not found in {coreutils_path}!")
            exit(1)


def run_test():
    for test in test_bins:
        binary = test[0]
        binary_path = coreutils_path + binary

        print(f"[{BLUE}TEST{CLEAR}] Testing {binary} ... ", end="")
        sys.stdout.flush()

        #retrowriting
        cmd(f"python3 -m arm.librw.rw {binary_path} /tmp/{binary}_rw.s")
        cmd(f"gcc -g /tmp/{binary}_rw.s -o /tmp/{binary}_rw.out")

        #exec with each possible arg
        for args in test[1]:
            output_rw = cmd(f"/tmp/{binary}_rw.out {args}")
            output    = cmd(f"{binary_path} {args}")
            if output != output_rw:
                critical(f"Output of {binary}_rw: {output_rw}")
                critical(f"Output of {binary}: {output}")
                assert False

        print(f"{GREEN}PASSED{CLEAR}")



if __name__ == "__main__":
    run_test()

