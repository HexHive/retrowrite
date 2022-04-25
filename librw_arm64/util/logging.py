import sys

DEBUG_LOG = False

CLEAR="\x1b[0m"
BLUE="\x1b[36m"
GREEN="\x1b[32m"
CRITICAL="\x1b[41m"


def debug(*s, end="\n"):
    if DEBUG_LOG:
        print(f"[{BLUE}DEBUG{CLEAR}]", end=end, *s)
        sys.stdout.flush()

def info(*s, end="\n"):
    print(f"[{GREEN}INFO{CLEAR}]", end=end, *s)

def critical(*s, end="\n"):
    print(f"[{CRITICAL}CRITICAL{CLEAR}]", end=end, *s)
