import sys

DEBUG_LOG = False

CLEAR="\x1b[0m"
BLUE="\x1b[36m"
GREEN="\x1b[32m"
CRITICAL="\x1b[41m"


def debug(s, end="\n"):
    if DEBUG_LOG:
        print(f"[{BLUE}DEBUG{CLEAR}] {s}", end=end)
        sys.stdout.flush()

def info(s, end="\n"):
    print(f"[{GREEN}INFO{CLEAR}] {s}", end=end)

def critical(s, end="\n"):
    print(f"[{CRITICAL}CRITICAL{CLEAR}] {s}", end=end)
