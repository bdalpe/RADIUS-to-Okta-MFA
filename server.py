#!/usr/bin/python
from __future__ import print_function
from pyrad.dictionary import Dictionary
from pyrad.server import Server, RemoteHost
from pyrad.packet import AccessReject, AccessAccept
import logging
from okta import OktaAPI, ResponseCodes
import os
import sys
import threading

logging.basicConfig(level="INFO",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")
logger = logging.getLogger(__name__)


class RadiusServer(Server):
    def __init__(self, *args, **kwargs):
        self.okta = OktaAPI(url=args[0], key=args[1])

        super().__init__(**kwargs)

    def auth_handler(self, pkt):
        user_name = pkt["User-Name"][0][
                    pkt["User-Name"][0].find("\\") + 1 if pkt["User-Name"][0].find("\\") > 0 else 0:]

        logger.info("Received an authentication request for {}.".format(user_name))
        logger.debug("Attributes: ")
        for attr in pkt.keys():
            logger.debug("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt, **{
            "Proxy-State": pkt["Proxy-State"]
        })
        reply.code = AccessReject

        try:
            if os.environ.get('OKTA_USE_SAMACCOUNTNAME'):
                u = self.okta.get_user_by_samaccountname(user_name)
            else:
                u = self.okta.get_user_id(user_name)
            f = self.okta.get_user_push_factor(u)
            if f is not None:
                push = self.okta.push_verify(u, f["id"])
                if push == ResponseCodes.SUCCESS:
                    logger.info("Push approved by {}.".format(user_name))
                    reply.code = AccessAccept
                else:
                    logger.warning("Push was rejected or timed out for {}!".format(user_name))
            else:
                logger.warning("{} does not have an Okta push factor enrolled!".format(user_name))
        except Exception as e:
            logger.exception("There was a problem with the Okta MFA", e)

        self.SendReplyPacket(pkt.fd, reply)

    def HandleAuthPacket(self, pkt):
        thread = threading.Thread(target=self.auth_handler, args=(pkt, ))
        thread.start()


def run():
    # Check to make sure env variables are set
    if not all(v in os.environ for v in ["OKTA_API_KEY", "OKTA_TENANT", "RADIUS_SECRET"]):
        logger.error("Missing environment variables!")
        sys.exit("Missing environment variables!")

    # Create server and read the attribute dictionary
    srv = RadiusServer(
        os.getenv('OKTA_TENANT'),
        os.getenv('OKTA_API_KEY'),
        dict=Dictionary("dictionary"),
        coa_enabled=False
    )

    # Add clients (address, secret, name)
    srv.hosts["0.0.0.0"] = RemoteHost("0.0.0.0", os.getenv("RADIUS_SECRET").encode(), "0.0.0.0")
    srv.BindToAddress("0.0.0.0")

    logger.info("Starting server...")

    # Run the RADIUS server
    srv.Run()


if __name__ == '__main__':
    run()
