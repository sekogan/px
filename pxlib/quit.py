import os
import sys
import time
import traceback

from pxlib.glob import *

try:
    import psutil
except ImportError:
    pprint("Requires module psutil")
    sys.exit()

if getattr(os, "getppid", None) == None:
    os.getppid = psutil.Process().ppid

###
# Exit related

def quit(force=False):
    count = 0
    mypids = [os.getpid(), os.getppid()]
    for pid in sorted(psutil.pids(), reverse=True):
        if pid in mypids:
            continue

        try:
            p = psutil.Process(pid)
            if p.exe().lower() == sys.executable.lower():
                count += 1
                if force:
                    p.kill()
                else:
                    p.send_signal(signal.CTRL_C_EVENT)
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError, SystemError):
            pass
        except:
            traceback.print_exc(file=sys.stdout)

    if count != 0:
        if force:
            sys.stdout.write(".")
        else:
            sys.stdout.write("Quitting Px ..")
            time.sleep(4)
        sys.stdout.flush()
        quit(True)
    else:
        if force:
            pprint(" DONE")
        else:
            pprint("Px is not running")

    sys.exit()

def handle_exceptions(extype, value, tb):
    # Create traceback log
    lst = (traceback.format_tb(tb, None) +
        traceback.format_exception_only(extype, value))
    tracelog = '\nTraceback (most recent call last):\n' + "%-20s%s\n" % (
        "".join(lst[:-1]), lst[-1])

    if State.logger != None:
        pprint(tracelog)
    else:
        sys.stderr.write(tracelog)

        # Save to debug.log
        dbg = open(dfile(), 'w')
        dbg.write(tracelog)
        dbg.close()
