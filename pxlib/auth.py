import base64
import os
import sys
import traceback

from pxlib.glob import *

try:
    import pywintypes
    import sspi
except ImportError:
    pprint("Requires module pywin32")
    sys.exit()

try:
    import winkerberos
except ImportError:
    pprint("Requires module winkerberos")
    sys.exit()

try:
    import ntlm_auth.ntlm
except ImportError:
    pprint("Requires module ntlm-auth")
    sys.exit()

try:
    import keyring
except ImportError:
    pprint("Requires module keyring")
    sys.exit()

# Python 2.x vs 3.x support
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

###
# Auth support

def b64decode(val):
    try:
        return base64.decodebytes(val.encode("utf-8"))
    except AttributeError:
        return base64.decodestring(val)

def b64encode(val):
    try:
        return base64.encodebytes(val.encode("utf-8"))
    except AttributeError:
        return base64.encodestring(val)

class AuthMessageGenerator:
    def __init__(self, proxy_type, proxy_server_address):
        pwd = ""
        if State.username:
            key = State.username
            if State.domain != "":
                key = State.domain + "\\" + State.username
            pwd = keyring.get_password("Px", key)

        if proxy_type == "NTLM":
            if not pwd:
                self.ctx = sspi.ClientAuth("NTLM",
                  os.environ.get("USERNAME"), scflags=0)
                self.get_response = self.get_response_sspi
            else:
                self.ctx = ntlm_auth.ntlm.NtlmContext(
                    State.username, pwd, State.domain, "", ntlm_compatibility=3)
                self.get_response = self.get_response_ntlm
        elif proxy_type == "BASIC":
            if not State.username:
                dprint("No username configured for Basic authentication")
            elif not pwd:
                dprint("No password configured for Basic authentication")
            else:
                # Colons are forbidden in usernames and passwords for basic auth
                # but since this can happen very easily, we make a special check
                # just for colons so people immediately understand that and don't
                # have to look up other resources.
                if ":" in State.username or ":" in pwd:
                    dprint("Credentials contain invalid colon character")
                else:
                    # Additionally check for invalid control characters as per
                    # RFC5234 Appendix B.1 (section CTL)
                    illegal_control_characters = "".join(
                        chr(i) for i in range(0x20)) + "\u007F"

                    if any(char in State.username or char in pwd
                            for char in illegal_control_characters):
                        dprint("Credentials contain invalid characters: %s" % ", ".join("0x" + "%x" % ord(char) for char in illegal_control_characters))
                    else:
                        # Remove newline appended by base64 function
                        self.ctx = b64encode(
                            "%s:%s" % (State.username, pwd))[:-1].decode()
            self.get_response = self.get_response_basic
        else:
            principal = None
            if pwd:
                if State.domain:
                    principal = (urlparse.quote(State.username) + "@" +
                        urlparse.quote(State.domain) + ":" + urlparse.quote(pwd))
                else:
                    principal = (urlparse.quote(State.username) + ":" +
                        urlparse.quote(pwd))

            _, self.ctx = winkerberos.authGSSClientInit("HTTP@" +
                proxy_server_address, principal=principal, gssflags=0,
                mech_oid=winkerberos.GSS_MECH_OID_SPNEGO)
            self.get_response = self.get_response_wkb

    def get_response_sspi(self, challenge=None):
        dprint("pywin32 SSPI")
        if challenge:
            challenge = b64decode(challenge)
        output_buffer = None
        try:
            error_msg, output_buffer = self.ctx.authorize(challenge)
        except pywintypes.error:
            traceback.print_exc(file=sys.stdout)
            return None

        response_msg = b64encode(output_buffer[0].Buffer)
        response_msg = response_msg.decode("utf-8").replace('\012', '')
        return response_msg

    def get_response_wkb(self, challenge=""):
        dprint("winkerberos SSPI")
        try:
            winkerberos.authGSSClientStep(self.ctx, challenge)
            auth_req = winkerberos.authGSSClientResponse(self.ctx)
        except winkerberos.GSSError:
            traceback.print_exc(file=sys.stdout)
            return None

        return auth_req

    def get_response_ntlm(self, challenge=""):
        dprint("ntlm-auth")
        if challenge:
            challenge = b64decode(challenge)
        response_msg = b64encode(self.ctx.step(challenge))
        response_msg = response_msg.decode("utf-8").replace('\012', '')
        return response_msg

    def get_response_basic(self, challenge=""):
        dprint("basic")
        return self.ctx
