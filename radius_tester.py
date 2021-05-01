from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet
from secrets import token_hex
import getpass

SERVER = "localhost"
USERNAME = "your_okta_username"
PASSWORD = getpass.getpass(prompt="Enter the password for {}: ".format(USERNAME))
RADIUS_SECRET = b"$upers3cret"

srv = Client(server=SERVER, secret=RADIUS_SECRET, dict=Dictionary("dictionary"), timeout=30)

# create request
req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=USERNAME, NAS_Identifier="localhost")
req["User-Password"] = req.PwCrypt(PASSWORD)
req["Proxy-State"] = token_hex(8).encode("ascii")

# send request
reply = srv.SendPacket(req)

if reply.code == pyrad.packet.AccessAccept:
    print("access accepted")
else:
    print("access denied")

print("Attributes returned by server:")
for i in reply.keys():
    print("%s: %s" % (i, reply[i]))
