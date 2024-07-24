import sys
import subprocess
import os
import re
from urllib.parse import urlparse


MOVE_CURSOR_UP_ONE_LINE = '\x1b[1A' 
ERASE_CURRENT_LINE = '\x1b[2K'

# Time intervals for display
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
)

def display_time(seconds, granularity=3):
    result = []
    seconds += 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append(f"{value}{name}")
    return ' '.join(result[:granularity])

def terminal_size():
    try:
        output = subprocess.check_output(['stty', 'size']).decode().strip()
        rows, columns = map(int, output.split())
        return columns
    except (subprocess.CalledProcessError, ValueError):
        return 20

def url_maker(url):
    if not re.match(r'https?://', url):
        url = 'http://' + url
    parsed = urlparse(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    result = "0% packet loss" in open('rs_net').read()
    os.remove('rs_net')
    return result

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BG_ERR_TXT = '\033[41m'
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT = '\033[43m'
    BG_LOW_TXT = '\033[44m'
    BG_INFO_TXT = '\033[42m'
    BG_SCAN_TXT_START = '\x1b[6;30;47m'
    BG_SCAN_TXT_END = '\x1b[0m'

    @staticmethod
    def white():
        return '\033[97m'

def vul_info(val):
    if val == 'c':
        return bcolors.BG_CRIT_TXT + " critical " + bcolors.ENDC
    elif val == 'h':
        return bcolors.BG_HIGH_TXT + " high " + bcolors.ENDC
    elif val == 'm':
        return bcolors.BG_MED_TXT + " medium " + bcolors.ENDC
    elif val == 'l':
        return bcolors.BG_LOW_TXT + " low " + bcolors.ENDC
    else:
        return bcolors.BG_INFO_TXT + " info " + bcolors.ENDC

proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med = bcolors.WARNING + "●" + bcolors.ENDC
proc_low = bcolors.OKGREEN + "●" + bcolors.ENDC

def vul_remed_info(v1, v2, v3):
    print(bcolors.BOLD + "Security Risk Level" + bcolors.ENDC)
    print("\t" + vul_info(v2) + " " + bcolors.WARNING + str(tool_resp[v1][0]) + bcolors.ENDC)
    print(bcolors.BOLD + "Issue Description" + bcolors.ENDC)
    print("\t" + bcolors.BADFAIL + str(tools_fix[v3-1][1]) + bcolors.ENDC)
    print(bcolors.BOLD + "Mitigation Steps" + bcolors.ENDC)
    print("\t" + bcolors.OKGREEN + str(tools_fix[v3-1][2]) + bcolors.ENDC)

def helper():
    print(bcolors.OKBLUE + "Information:" + bcolors.ENDC)
    print("------------")
    print("\t./probeforweb.py example.com: Scans the domain example.com.")
    print("\t./probeforweb.py example.com --skip dmitry --skip theHarvester: Skip the 'dmitry' and 'theHarvester' tests.")
    print("\t./probeforweb.py example.com --nospinner: Disable the idle loader/spinner.")
    print("\t./probeforweb.py --update   : Updates the scanner to the latest version.")
    print("\t./probeforweb.py --help     : Displays this help context.")
    print(bcolors.OKBLUE + "Interactive:" + bcolors.ENDC)
    print("------------")
    print("\tCtrl+C: Skips current test.")
    print("\tCtrl+Z: Quits probeforweb.")
    print(bcolors.OKBLUE + "Legends:" + bcolors.ENDC)
    print("--------")
    print("\t[" + proc_high + "]: Scan process may take longer times (not predictable).")
    print("\t[" + proc_med + "]: Scan process may take less than 10 minutes.")
    print("\t[" + proc_low + "]: Scan process may take less than a minute or two.")
    print(bcolors.OKBLUE + "Vulnerability Information:" + bcolors.ENDC)
    print("--------------------------")
    print("\t" + vul_info('c') + ": Requires immediate attention as it may lead to compromise or service unavailability.")
    print("\t" + vul_info('h') + "    : May not lead to an immediate compromise, but there are considerable chances for probability.")
    print("\t" + vul_info('m') + "  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack.")
    print("\t" + vul_info('l') + "     : Not a serious issue, but it is recommended to tend to the finding.")
    print("\t" + vul_info('i') + "    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n")

def clear():
    sys.stdout.write("\033[F")
    sys.stdout.write("\033[K")

def logo():
    class bcolors:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKCYAN = '\033[96m'
        OKGREEN = '\033[92m'
        WHITE = '0\33[97m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

    print(bcolors.WARNING)
    logo_ascii = f"""
{bcolors.WHITE}  modify and change the code for web vulnerability scanner"""
    print(logo_ascii)
    print(bcolors.ENDC)
