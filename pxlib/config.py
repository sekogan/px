import os
import socket
import sys

from pxlib.glob import *

import pxlib.help
import pxlib.proxy
import pxlib.windows

try:
    import netaddr
except ImportError:
    pprint("Requires module netaddr")
    sys.exit()

# Python 2.x vs 3.x support
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

###
# Parse settings and command line

def parse_proxy(proxystrs):
    if not proxystrs:
        return []

    servers = []
    for proxystr in [i.strip() for i in proxystrs.split(",")]:
        pserver = [i.strip() for i in proxystr.split(":")]
        if len(pserver) == 1:
            pserver.append(80)
        elif len(pserver) == 2:
            try:
                pserver[1] = int(pserver[1])
            except ValueError:
                pprint("Bad proxy server port: " + pserver[1])
                sys.exit()
        else:
            pprint("Bad proxy server definition: " + proxystr)
            sys.exit()

        if tuple(pserver) not in servers:
            servers.append(tuple(pserver))

    return servers

def parse_ip_ranges(iprangesconfig):
    ipranges = netaddr.IPSet([])

    iprangessplit = [i.strip() for i in iprangesconfig.split(",")]
    for iprange in iprangessplit:
        if not iprange:
            continue

        try:
            if "-" in iprange:
                spl = iprange.split("-", 1)
                ipns = netaddr.IPRange(spl[0], spl[1])
            elif "*" in iprange:
                ipns = netaddr.IPGlob(iprange)
            else:
                ipns = netaddr.IPNetwork(iprange)
            ipranges.add(ipns)
        except:
            pprint("Bad IP definition: %s" % iprangesconfig)
            sys.exit()
    return ipranges

def parse_allow(allow):
    State.allow = parse_ip_ranges(allow)

def parse_noproxy(noproxy):
    State.noproxy = parse_ip_ranges(noproxy)

def set_useragent(useragent):
    State.useragent = useragent

def set_username(username):
    ud = username.split("\\")
    if len(ud) == 2:
        State.username = ud[1]
        State.domain = ud[0]
    else:
        State.username = username

def set_pac(pac):
    if pac == "":
        return

    pacproxy = False
    if pac.startswith("http"):
        pacproxy = True

    elif pac.startswith("file"):
        pac = pxlib.proxy.file_url_to_local_path(pac)

    if os.path.exists(pac):
        pacproxy = True

    if pacproxy:
        State.pac = pac
    else:
        pprint("Unsupported PAC location or file not found: %s" % pac)
        sys.exit()

def set_auth(auth):
    if auth.upper() not in ["NTLM", "KERBEROS", "BASIC", ""]:
        pprint("Bad proxy auth type: %s" % auth)
        sys.exit()
    if auth != "":
        State.auth = auth

def cfg_int_init(section, name, default, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    try:
        val = int(val)
    except ValueError:
        pprint("Invalid integer value for " + section + ":" + name)

    State.config.set(section, name, str(val))

def cfg_float_init(section, name, default, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    try:
        val = float(val)
    except ValueError:
        pprint("Invalid float value for " + section + ":" + name)

    State.config.set(section, name, str(val))

def cfg_str_init(section, name, default, proc=None, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    State.config.set(section, name, val)

    if proc != None:
        proc(val)

def save():
    with open(State.ini, "w") as cfgfile:
        State.config.write(cfgfile)
    pprint("Saved config to " + State.ini + "\n")
    with open(State.ini, "r") as cfgfile:
        sys.stdout.write(cfgfile.read())

    sys.exit()

def parse_config():
    if "--debug" in sys.argv:
        State.logger = Log(dfile(), "w")

    if getattr(sys, "frozen", False) != False or "pythonw.exe" in sys.executable:
        pxlib.windows.attach_console()

    if "-h" in sys.argv or "--help" in sys.argv:
        pprint(pxlib.help.HELP)
        sys.exit()

    # Load configuration file
    State.config = configparser.ConfigParser()
    State.ini = os.path.join(os.path.dirname(get_script_path()), State.ini)
    for i in range(len(sys.argv)):
        if "=" in sys.argv[i]:
            val = sys.argv[i].split("=")[1]
            if "--config=" in sys.argv[i]:
                State.ini = val
                if not os.path.exists(val) and "--save" not in sys.argv:
                    pprint("Could not find config file: " + val)
                    sys.exit()
    if os.path.exists(State.ini):
        State.config.read(State.ini)

    # [proxy] section
    if "proxy" not in State.config.sections():
        State.config.add_section("proxy")

    cfg_str_init("proxy", "server", "")
    cfg_str_init("proxy", "pac", "", set_pac)
    cfg_int_init("proxy", "port", "3128")
    cfg_str_init("proxy", "listen", "127.0.0.1")
    cfg_str_init("proxy", "allow", "*.*.*.*", parse_allow)
    cfg_int_init("proxy", "gateway", "0")
    cfg_int_init("proxy", "hostonly", "0")
    cfg_str_init("proxy", "noproxy", "", parse_noproxy)
    cfg_str_init("proxy", "useragent", "", set_useragent)
    cfg_str_init("proxy", "username", "", set_username)
    cfg_str_init("proxy", "auth", "", set_auth)

    # [settings] section
    if "settings" not in State.config.sections():
        State.config.add_section("settings")

    cfg_int_init("settings", "workers", "2")
    cfg_int_init("settings", "threads", "5")
    cfg_int_init("settings", "idle", "30")
    cfg_float_init("settings", "socktimeout", "20.0")
    cfg_int_init("settings", "proxyreload", "60")
    cfg_int_init("settings", "foreground", "0")

    cfg_int_init("settings", "log", "0" if State.logger is None else "1")
    if State.config.get("settings", "log") == "1" and State.logger is None:
        State.logger = Log(dfile(), "w")

    # Command line flags
    for i in range(len(sys.argv)):
        if "=" in sys.argv[i]:
            val = sys.argv[i].split("=")[1]
            if "--proxy=" in sys.argv[i] or "--server=" in sys.argv[i]:
                cfg_str_init("proxy", "server", val, None, True)
            elif "--pac=" in sys.argv[i]:
                cfg_str_init("proxy", "pac", val, set_pac, True)
            elif "--listen=" in sys.argv[i]:
                cfg_str_init("proxy", "listen", val, None, True)
            elif "--port=" in sys.argv[i]:
                cfg_int_init("proxy", "port", val, True)
            elif "--allow=" in sys.argv[i]:
                cfg_str_init("proxy", "allow", val, parse_allow, True)
            elif "--noproxy=" in sys.argv[i]:
                cfg_str_init("proxy", "noproxy", val, parse_noproxy, True)
            elif "--useragent=" in sys.argv[i]:
                cfg_str_init("proxy", "useragent", val, set_useragent, True)
            elif "--username=" in sys.argv[i]:
                cfg_str_init("proxy", "username", val, set_username, True)
            elif "--auth=" in sys.argv[i]:
                cfg_str_init("proxy", "auth", val, set_auth, True)
            else:
                for j in ["workers", "threads", "idle", "proxyreload"]:
                    if "--" + j + "=" in sys.argv[i]:
                        cfg_int_init("settings", j, val, True)

                for j in ["socktimeout"]:
                    if "--" + j + "=" in sys.argv[i]:
                        cfg_float_init("settings", j, val, True)

    if "--gateway" in sys.argv:
        cfg_int_init("proxy", "gateway", "1", True)

    if "--hostonly" in sys.argv:
        cfg_int_init("proxy", "hostonly", "1", True)

    if "--foreground" in sys.argv:
        cfg_int_init("settings", "foreground", "1", True)

    ###
    # Dependency propagation

    # If gateway mode
    if State.config.getint("proxy", "gateway") == 1:
        # Listen on all interfaces
        cfg_str_init("proxy", "listen", "", None, True)

    # If hostonly mode
    if State.config.getint("proxy", "hostonly") == 1:
        State.hostonly = True

        # Listen on all interfaces
        cfg_str_init("proxy", "listen", "", None, True)

        # If not gateway mode or gateway with default allow rules
        if (State.config.getint("proxy", "gateway") == 0 or
                (State.config.getint("proxy", "gateway") == 1 and
                 State.config.get("proxy", "allow") in [
                    "*.*.*.*", "0.0.0.0/0"])):
            # Purge allow rules
            cfg_str_init("proxy", "allow", "", parse_allow, True)

    State.proxy_server = parse_proxy(State.config.get("proxy", "server"))

    if "--install" in sys.argv:
        pxlib.windows.install()
    elif "--uninstall" in sys.argv:
        pxlib.windows.uninstall()
    elif "--quit" in sys.argv:
        quit()
    elif "--save" in sys.argv:
        save()

    if State.proxy_server:
        State.proxy_mode = MODE_CONFIG
    elif State.pac:
        State.proxy_mode = MODE_CONFIG_PAC
    else:
        pxlib.proxy.load_proxy(quiet=True)

    if State.proxy_mode == MODE_NONE and not State.config.get(
            "proxy", "noproxy"):
        pprint("No proxy server or noproxy list defined")
        sys.exit()

    socket.setdefaulttimeout(State.config.getfloat("settings", "socktimeout"))
