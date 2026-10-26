import subprocess
from util.logger import inf, err, wrn, dbg

def crawling(target):
    inf(f"Crawling module called with target: {target}")
    inf(f"Starting crawling on target: {target}")

    katana = input("do you want use tools katana y/N ").lower()
    gau = input("do you want use tools gau y/N ").lower()
    ffuf = input("do you want use tools ffuf y/N ").lower()

    if katana == 'y':
        inf(f"Starting Katana crawling on target: {target}")
        try:
            subprocess.run(['katana', '-u', target, '-o', 'katana_output.txt'], check=True)
            inf("Katana crawling completed successfully.")
        except subprocess.CalledProcessError as e:
            err(f"Katana crawling failed: {e}")
    else:
        err("Katana crawling skipped.")

    if gau == 'y':
        inf(f"Starting Gau crawling on target: {target}")
        try:
            subprocess.run(['gau', '--output', 'gau_output.txt', target], check=True)
            inf("Gau crawling completed successfully.")
        except subprocess.CalledProcessError as e:
            err(f"Gau crawling failed: {e}")
    else:
        err("Gau crawling skipped.")

    if ffuf == 'y':
        inf(f"Starting Ffuf crawling on target: {target}")
        try:
            subprocess.run(['ffuf', '-u', f"{target}/FUZZ", '-o', 'ffuf_output.txt'], check=True)
            inf("Ffuf crawling completed successfully.")
        except subprocess.CalledProcessError as e:
            err(f"Ffuf crawling failed: {e}")
    else:
        err("Ffuf crawling skipped.")