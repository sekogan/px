import ctypes
import ctypes.wintypes
import sys

from pxlib.glob import *

try:
    import psutil
except ImportError:
    pprint("Requires module psutil")
    sys.exit()
try:
    import keyring.backends.Windows

    keyring.set_keyring(keyring.backends.Windows.WinVaultKeyring())
except ImportError:
    pprint("Requires module keyring")
    sys.exit()

# Python 2.x vs 3.x support
try:
    import winreg
except ImportError:
    import _winreg as winreg

    PermissionError = WindowsError

import pxlib.config

# Windows version
#  6.1 = Windows 7
#  6.2 = Windows 8
#  6.3 = Windows 8.1
# 10.0 = Windows 10
WIN_VERSION = float(
    str(sys.getwindowsversion().major) + "." +
    str(sys.getwindowsversion().minor))

###
# Proxy detection

class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(ctypes.Structure):
    _fields_ = [("fAutoDetect", ctypes.wintypes.BOOL),
                # "Automatically detect settings"
                ("lpszAutoConfigUrl", ctypes.wintypes.LPWSTR),
                # "Use automatic configuration script, Address"
                ("lpszProxy", ctypes.wintypes.LPWSTR),
                # "1.2.3.4:5" if "Use the same proxy server for all protocols",
                # else advanced
                # "ftp=1.2.3.4:5;http=1.2.3.4:5;https=1.2.3.4:5;socks=1.2.3.4:5"
                ("lpszProxyBypass", ctypes.wintypes.LPWSTR),
                # ";"-separated list
                # "Bypass proxy server for local addresses" adds "<local>"
               ]

class WINHTTP_AUTOPROXY_OPTIONS(ctypes.Structure):
    _fields_ = [("dwFlags", ctypes.wintypes.DWORD),
                ("dwAutoDetectFlags", ctypes.wintypes.DWORD),
                ("lpszAutoConfigUrl", ctypes.wintypes.LPCWSTR),
                ("lpvReserved", ctypes.c_void_p),
                ("dwReserved", ctypes.wintypes.DWORD),
                ("fAutoLogonIfChallenged", ctypes.wintypes.BOOL), ]

class WINHTTP_PROXY_INFO(ctypes.Structure):
    _fields_ = [("dwAccessType", ctypes.wintypes.DWORD),
                ("lpszProxy", ctypes.wintypes.LPCWSTR),
                ("lpszProxyBypass", ctypes.wintypes.LPCWSTR), ]

# Parameters for WinHttpOpen, http://msdn.microsoft.com/en-us/library/aa384098(VS.85).aspx
WINHTTP_NO_PROXY_NAME = 0
WINHTTP_NO_PROXY_BYPASS = 0
WINHTTP_FLAG_ASYNC = 0x10000000

# dwFlags values
WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002

# dwAutoDetectFlags values
WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002

# dwAccessType values
WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
WINHTTP_ACCESS_TYPE_NO_PROXY = 1
WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4

# Error messages
WINHTTP_ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT = 12167

def winhttp_find_proxy_for_url(
        url, autodetect=False, pac_url=None, autologon=True):
    # Fix issue #51
    ACCESS_TYPE = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
    if WIN_VERSION < 6.3:
        ACCESS_TYPE = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY

    ctypes.windll.winhttp.WinHttpOpen.restype = ctypes.c_void_p
    hInternet = ctypes.windll.winhttp.WinHttpOpen(
        ctypes.wintypes.LPCWSTR("Px"),
        ACCESS_TYPE, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC)
    if not hInternet:
        dprint("WinHttpOpen failed: " + str(ctypes.GetLastError()))
        return ""

    autoproxy_options = WINHTTP_AUTOPROXY_OPTIONS()
    if pac_url:
        autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
        autoproxy_options.dwAutoDetectFlags = 0
        autoproxy_options.lpszAutoConfigUrl = pac_url
    elif autodetect:
        autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
        autoproxy_options.dwAutoDetectFlags = (
            WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A)
        autoproxy_options.lpszAutoConfigUrl = 0
    else:
        return ""
    autoproxy_options.fAutoLogonIfChallenged = autologon

    proxy_info = WINHTTP_PROXY_INFO()

    # Fix issue #43
    ctypes.windll.winhttp.WinHttpGetProxyForUrl.argtypes = [ctypes.c_void_p,
        ctypes.wintypes.LPCWSTR, ctypes.POINTER(WINHTTP_AUTOPROXY_OPTIONS),
        ctypes.POINTER(WINHTTP_PROXY_INFO)]
    ok = ctypes.windll.winhttp.WinHttpGetProxyForUrl(
        hInternet, ctypes.wintypes.LPCWSTR(url),
        ctypes.byref(autoproxy_options), ctypes.byref(proxy_info))
    if not ok:
        error = ctypes.GetLastError()
        dprint("WinHttpGetProxyForUrl error %s" % error)
        if error == WINHTTP_ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT:
            dprint("Could not download PAC file, trying DIRECT instead")
            return "DIRECT"
        return ""

    if proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY:
        # Note: proxy_info.lpszProxyBypass makes no sense here!
        if not proxy_info.lpszProxy:
            dprint('WinHttpGetProxyForUrl named proxy without name')
            return ""
        return proxy_info.lpszProxy.replace(" ", ",").replace(";", ",").replace(
            ",DIRECT", "") # Note: We only see the first!
    if proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY:
        return "DIRECT"

    # WinHttpCloseHandle()
    dprint("WinHttpGetProxyForUrl accesstype %s" % (proxy_info.dwAccessType,))
    return ""

def load_proxy(quiet):
    # Start with clean proxy mode and server list
    proxy_mode = MODE_NONE
    proxy_servers = []

    # Get proxy info from Internet Options
    ie_proxy_config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
    ok = ctypes.windll.winhttp.WinHttpGetIEProxyConfigForCurrentUser(
        ctypes.byref(ie_proxy_config))
    if not ok:
        if not quiet:
            dprint(ctypes.GetLastError())
    else:
        if ie_proxy_config.fAutoDetect:
            proxy_mode = MODE_AUTO
        elif ie_proxy_config.lpszAutoConfigUrl:
            State.pac = ie_proxy_config.lpszAutoConfigUrl
            proxy_mode = MODE_PAC
            if not quiet:
                dprint("AutoConfigURL = " + State.pac)
        else:
            # Manual proxy
            proxies = []
            proxies_str = ie_proxy_config.lpszProxy or ""
            for proxy_str in proxies_str.lower().replace(
                    ' ', ';').split(';'):
                if '=' in proxy_str:
                    scheme, proxy = proxy_str.split('=', 1)
                    if scheme.strip() != "ftp":
                        proxies.append(proxy)
                elif proxy_str:
                    proxies.append(proxy_str)
            if proxies:
                proxy_servers = pxlib.config.parse_proxy(",".join(proxies))
                proxy_mode = MODE_MANUAL

            # Proxy exceptions into noproxy
            bypass_str = ie_proxy_config.lpszProxyBypass or "" # FIXME: Handle "<local>"
            bypasses = [h.strip() for h in bypass_str.lower().replace(
                ' ', ';').split(';')]
            for bypass in bypasses:
                try:
                    ipns = netaddr.IPGlob(bypass)
                    State.noproxy.add(ipns)
                    if not quiet:
                        dprint("Noproxy += " + bypass)
                except:
                    State.noproxy_hosts.append(bypass)
                    if not quiet:
                        dprint("Noproxy hostname += " + bypass)

    return (proxy_mode, proxy_servers)

###
# Install Px to startup

def check_installed():
    ret = True
    runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
    try:
        winreg.QueryValueEx(runkey, "Px")
    except:
        ret = False
    winreg.CloseKey(runkey)

    return ret

def install():
    if check_installed() is False:
        runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
            winreg.KEY_WRITE)
        winreg.SetValueEx(runkey, "Px", 0, winreg.REG_EXPAND_SZ,
            get_script_cmd())
        winreg.CloseKey(runkey)
        pprint("Px installed successfully")
    else:
        pprint("Px already installed")

    sys.exit()

def uninstall():
    if check_installed() is True:
        runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
            winreg.KEY_WRITE)
        winreg.DeleteValue(runkey, "Px")
        winreg.CloseKey(runkey)
        pprint("Px uninstalled successfully")
    else:
        pprint("Px is not installed")

    sys.exit()

###
# Attach/detach console

def attach_console():
    if ctypes.windll.kernel32.GetConsoleWindow() != 0:
        dprint("Already attached to a console")
        return

    # Find parent cmd.exe if exists
    pid = os.getpid()
    while True:
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            # No such parent - started without console
            pid = -1
            break

        if os.path.basename(p.name()).lower() in [
                "cmd", "cmd.exe", "powershell", "powershell.exe"]:
            # Found it
            break

        # Search parent
        pid = p.ppid()

    # Not found, started without console
    if pid == -1:
        dprint("No parent console to attach to")
        return

    dprint("Attaching to console " + str(pid))
    if ctypes.windll.kernel32.AttachConsole(pid) == 0:
        dprint("Attach failed with error " +
            str(ctypes.windll.kernel32.GetLastError()))
        return

    if ctypes.windll.kernel32.GetConsoleWindow() == 0:
        dprint("Not a console window")
        return

    reopen_stdout()

def detach_console():
    if ctypes.windll.kernel32.GetConsoleWindow() == 0:
        return

    restore_stdout()

    if not ctypes.windll.kernel32.FreeConsole():
        dprint("Free console failed with error " +
            str(ctypes.windll.kernel32.GetLastError()))
    else:
        dprint("Freed console successfully")
