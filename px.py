"Px is an HTTP proxy server to automatically authenticate through an NTLM proxy"

import multiprocessing
import sys

import pxlib.config
import pxlib.pool
import pxlib.quit

###
# Startup

def main():
    multiprocessing.freeze_support()
    sys.excepthook = pxlib.quit.handle_exceptions

    pxlib.config.parse_config()

    pxlib.pool.run_pool()

if __name__ == "__main__":
    main()
