#import utils
import os
import argparse
import sys
import functools
from util.banner import banner
from util.logger import inf, err, wrn, dbg
from module import (
    crawling,
    networking,
    scan,
    livecheck,
    whatweb,
    brute_path as brutepath,
    scanning_waf as waf,
    dns_recon as dnsrecon,
    dns_records as dnsrecords,
    nameserver as nameserver,
    http_probe as httpprobe,
    service_scan as servicescan,
    subdo as subdomain,
    brute_port as bruteport,
    vuln_scan as vulnscan
)

def main():
    os.system("cls" if os.name == "nt" else "clear") # clear
    banner()

    p = argparse.ArgumentParser(description='')
    p.add_argument('-u', '--url', type=str, required=True, metavar='URL', help="Target to scanning")
    p.add_argument('-scan', action='store_true', help='to start scanning')
    p.add_argument('-networking', action='store_true', help='to scan networking with nmap module')
    p.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    #p.add_argument('-h', '--help', action='help', help='show this help message and exit')
    p.add_argument('-brute-port', action='store_true', help='to start brute force port scanning')
    p.add_argument('-brute-path', action='store_true', help='to start brute force path scanning')
    p.add_argument('-subdo', action='store_true', help='to start subdomain scanning')
    p.add_argument('-livecheck', action='store_true', help='to start live check scanning in subdomain scanning')
    p.add_argument('-whatweb', action='store_true', help='to start whatweb scanning in subdomain scanning')
    p.add_argument('-scanninng-waf', action='store_true', help='to start scanning waf in subdomain scanning')
    p.add_argument('-dns-recon', action='store_true', help='to start dns recon scanning')
    p.add_argument('-dns-records', action='store_true', help='to start dns records scanning')
    p.add_argument('-nameserver', action='store_true', help='to start nameserver scanning')
    p.add_argument('-service-scan', action='store_true', help='to start service scan scanning')
    p.add_argument('-http-probe', action='store_true', help='to start http probe scanning')
    p.add_argument('-crawling', action='store_true', help='to start crawling scanning')
    p.add_argument('-vuln-scan', action='store_true', help='to start vuln scan scanning')

    __a__ = p.parse_args()

    def req(flag):
        def decorator(fn):
            def wrapper(*args, **kwargs):
                if not getattr(__a__, flag):
                    err(f"we have error in module {flag}")
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def log(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            dbg(f"running {fn.__name__} with args: {args}, kwargs: {kwargs}")
            try:
                result = fn(*args, **kwargs)
                dbg(f"{fn.__name__} returned {result}")
                return result
            except Exception as e:
                err(f"Error in {fn.__name__}: {e}")
                raise
        return wrapper

    try:
        scan_options = [
            "networking",
            "brute_port",
            "brute_path",
            "subdo",
            "livecheck",
            "whatweb",
            "scanninng_waf",
            "dns_recon",
            "dns_records",
            "nameserver",
            "service_scan",
            "http_probe",
            "crawling",
            "vuln_scan"
        ]

        selected = [
            option
            for option in scan_options
            if getattr(__a__, option, False)
        ]

        if not __a__.url:
            err("Please provide a valid URL to start scanning")

        if not selected:
            err("Please provide a valid option to start scanning")

    except ValueError as e:
        critical(e)

    except Exception as e:
        critical(e)

    scan_functions = {
        "scan": scan,
        "networking": networking,
        "brute_port": bruteport,
        "brute_path": brutepath,
        "subdo": subdomain,
        "livecheck": livecheck,
        "whatweb": whatweb,
        "scanninng_waf": waf,
        "dns_recon": dnsrecon,
        "dns_records": dnsrecords,
        "nameserver": nameserver,
        "service_scan": servicescan,
        "http_probe": httpprobe,
        "crawling": crawling,
        "vuln_scan": vulnscan,
    }

    for option, function in scan_functions.items():
        if getattr(__a__, option, False):
            function(__a__.url)

if __name__ == "__main__":
    main()