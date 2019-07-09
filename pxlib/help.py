import pxlib.version

HELP = """Px v%s

An HTTP proxy server to automatically authenticate through an NTLM proxy

Usage:
  px [FLAGS]
  python px.py [FLAGS]

Actions:
  --save
  Save configuration to px.ini or file specified with --config
    Allows setting up Px config directly from command line
    Values specified on CLI override any values in existing config file
    Values not specified on CLI or config file are set to defaults

  --install
  Add Px to the Windows registry to run on startup

  --uninstall
  Remove Px from the Windows registry

  --quit
  Quit a running instance of Px.exe

Configuration:
  --config=
  Specify config file. Valid file path, default: px.ini in working directory

  --proxy=  --server=  proxy:server= in INI file
  NTLM server(s) to connect through. IP:port, hostname:port
    Multiple proxies can be specified comma separated. Px will iterate through
    and use the one that works. Required field unless --noproxy is defined. If
    remote server is not in noproxy list and proxy is undefined, Px will reject
    the request

  --pac=  proxy:pac=
  PAC file to use to connect
    Use in place of server if PAC file should be loaded from a custom URL or
    file location instead of from Internet Options

  --listen=  proxy:listen=
  IP interface to listen on. Valid IP address, default: 127.0.0.1

  --port=  proxy:port=
  Port to run this proxy. Valid port number, default: 3128

  --gateway  proxy:gateway=
  Allow remote machines to use proxy. 0 or 1, default: 0
    Overrides 'listen' and binds to all interfaces

  --hostonly  proxy:hostonly=
  Allow only local interfaces to use proxy. 0 or 1, default: 0
    Px allows all IP addresses assigned to local interfaces to use the service.
    This allows local apps as well as VM or container apps to use Px when in a
    NAT config. Px does this by listening on all interfaces and overriding the
    allow list.

  --allow=  proxy:allow=
  Allow connection from specific subnets. Comma separated, default: *.*.*.*
    Whitelist which IPs can use the proxy. --hostonly overrides any definitions
    unless --gateway mode is also specified
    127.0.0.1 - specific ip
    192.168.0.* - wildcards
    192.168.0.1-192.168.0.255 - ranges
    192.168.0.1/24 - CIDR

  --noproxy=  proxy:noproxy=
  Direct connect to specific subnets like a regular proxy. Comma separated
    Skip the NTLM proxy for connections to these subnets
    127.0.0.1 - specific ip
    192.168.0.* - wildcards
    192.168.0.1-192.168.0.255 - ranges
    192.168.0.1/24 - CIDR

  --useragent=  proxy:useragent=
  Override or send User-Agent header on client's behalf

  --username=  proxy:username=
  Authentication to use when SSPI is unavailable. Format is domain\\username
  Service name "Px" and this username are used to retrieve the password using
  Python keyring. Px only retrieves credentials and storage should be done
  directly in the keyring backend.
    On Windows, Credential Manager is the backed and can be accessed from
    Control Panel > User Accounts > Credential Manager > Windows Credentials.
    Create a generic credential with Px as the network address, this username
    and corresponding password.

  --auth=  proxy:auth=
  Force instead of discovering upstream proxy type
    By default, Px will attempt to discover the upstream proxy type and either
    use pywin32/ntlm-auth for NTLM auth or winkerberos for Kerberos or Negotiate
    auth. This option will force either NTLM, Kerberos or Basic and not query the
    upstream proxy type.

  --workers=  settings:workers=
  Number of parallel workers (processes). Valid integer, default: 2

  --threads=  settings:threads=
  Number of parallel threads per worker (process). Valid integer, default: 5

  --idle=  settings:idle=
  Idle timeout in seconds for HTTP connect sessions. Valid integer, default: 30

  --socktimeout=  settings:socktimeout=
  Timeout in seconds for connections before giving up. Valid float, default: 20

  --proxyreload=  settings:proxyreload=
  Time interval in seconds before refreshing proxy info. Valid int, default: 60
    Proxy info reloaded from a PAC file found via WPAD or AutoConfig URL, or
    manual proxy info defined in Internet Options

  --foreground  settings:foreground=
  Run in foreground when frozen or with pythonw.exe. 0 or 1, default: 0
    Px will attach to the console and write to it even though the prompt is
    available for further commands. CTRL-C in the console will exit Px

  --debug  settings:log=
  Enable debug logging. default: 0
    Logs are written to working directory and over-written on startup
    A log is automatically created if Px crashes for some reason

  --uniqlog
  Generate unique log file names
    Prevents logs from being overwritten on subsequent runs. Also useful if
    running multiple instances of Px""" % pxlib.version.__version__
