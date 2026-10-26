import sys
import subprocess
from util.logger import err, inf, dbg, wrn, critical

def brute_port(target):
     inf(f"brute_port module called with target: {target}")