from __future__ import print_function

import multiprocessing
import os
import threading
import time
import sys

try:
    import netaddr
except ImportError:
    pprint("Requires module netaddr")
    sys.exit()

# Proxy modes - source of proxy info
MODE_NONE = 0
MODE_CONFIG = 1
MODE_AUTO = 2
MODE_PAC = 3
MODE_MANUAL = 4
MODE_CONFIG_PAC = 5

# Print if possible
def pprint(*objs):
    try:
        print(*objs)
    except:
        pass

class State(object):
    allow = netaddr.IPGlob("*.*.*.*")
    config = None
    domain = ""
    exit = False
    hostonly = False
    logger = None
    noproxy = netaddr.IPSet([])
    noproxy_hosts = []
    pac = ""
    proxy_mode = MODE_NONE
    proxy_refresh = None
    proxy_server = []
    proxy_type = {}
    stdout = None
    useragent = ""
    username = ""
    auth = None

    ini = "px.ini"
    max_disconnect = 3
    max_line = 65536 + 1

    # Locks for thread synchronization;
    # multiprocess sync isn't neccessary because State object is only shared by
    # threads but every process has it's own State object
    proxy_type_lock = threading.Lock()
    proxy_mode_lock = threading.Lock()

class Log(object):
    def __init__(self, name, mode):
        self.file = open(name, mode)
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
    def close(self):
        sys.stdout = self.stdout
        sys.stderr = self.stderr
        self.file.close()
    def write(self, data):
        try:
            self.file.write(data)
        except:
            pass
        if self.stdout is not None:
            self.stdout.write(data)
        self.flush()
    def flush(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        if self.stdout is not None:
            self.stdout.flush()

def get_script_path():
    if getattr(sys, "frozen", False) is False:
        # Script mode
        return os.path.normpath(os.path.join(os.getcwd(), sys.argv[0]))

    # Frozen mode
    return sys.executable

def get_script_cmd():
    spath = get_script_path()
    if os.path.splitext(spath)[1].lower() == ".py":
        return sys.executable + ' "%s"' % spath

    return spath

def dprint(msg):
    if State.logger is not None:
        # Do locking to avoid mixing the output of different threads as there are
        # two calls to print which could otherwise interleave
        sys.stdout.write(
            multiprocessing.current_process().name + ": " +
            threading.current_thread().name + ": " + str(int(time.time())) +
            ": " + sys._getframe(1).f_code.co_name + ": " + msg + "\n")

def dfile():
    name = multiprocessing.current_process().name
    if "--quit" in sys.argv:
        name = "quit"
    if "--uniqlog" in sys.argv:
        name = "%s-%f" % (name, time.time())
    logfile = os.path.join(os.path.dirname(get_script_path()),
        "debug-%s.log" % name)
    return logfile

def reopen_stdout():
    clrstr = "\r" + " " * 80 + "\r"
    if State.logger is None:
        State.stdout = sys.stdout
        sys.stdout = open("CONOUT$", "w")
        sys.stdout.write(clrstr)
    else:
        State.stdout = State.logger.stdout
        State.logger.stdout = open("CONOUT$", "w")
        State.logger.stdout.write(clrstr)

def restore_stdout():
    if State.logger is None:
        sys.stdout.close()
        sys.stdout = State.stdout
    else:
        State.logger.stdout.close()
        State.logger.stdout = State.stdout
