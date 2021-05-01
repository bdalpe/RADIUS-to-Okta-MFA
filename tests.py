import fcntl
import runpy
import socket
import unittest
import os
from unittest.mock import patch
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AuthPacket
from server import run, RadiusServer
from okta import OktaAPI, ResponseCodes, ThreadTTLContextManager


# From pyrad/tests/mock.py
class MockSocket:
    def __init__(self, domain, type, data=None):
        self.domain = domain
        self.type = type
        self.closed = False
        self.options = []
        self.address = None
        self.output = []

        if data is not None:
            (self.read_end, self.write_end) = os.pipe()
            fcntl.fcntl(self.write_end, fcntl.F_SETFL, os.O_NONBLOCK)
            os.write(self.write_end, data)
            self.data = data
        else:
            self.read_end = 1
            self.write_end = None

    def fileno(self):
        return self.read_end

    def bind(self, address):
        self.address = address

    def recv(self, buffer):
        return self.data[:buffer]

    def sendto(self, data, target):
        self.output.append((data, target))

    def setsockopt(self, level, opt, value):
        self.options.append((level, opt, value))

    def close(self):
        self.closed = True


# From pyrad/tests/testHost.py
class MockFd:
    data = None
    target = None

    def sendto(self, data, target):
        self.data = data
        self.target = target


def mocked_sessions(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    url_data = {
        'https://fake/api/v1/users/isaac.brock@example.com': {
            "id": "00ub0oNGTSWTBKOLGLNR",
            "status": "ACTIVE",
            "created": "2013-06-24T16:39:18.000Z",
            "activated": "2013-06-24T16:39:19.000Z",
            "statusChanged": "2013-06-24T16:39:19.000Z",
            "lastLogin": "2013-06-24T17:39:19.000Z",
            "lastUpdated": "2013-07-02T21:36:25.344Z",
            "passwordChanged": "2013-07-02T21:36:25.344Z",
            "profile": {
                "firstName": "Isaac",
                "lastName": "Brock",
                "email": "isaac.brock@example.com",
                "login": "isaac.brock@example.com",
                "mobilePhone": "555-415-1337"
            },
            "credentials": {
                "password": {},
                "recovery_question": {
                    "question": "Who's a major player in the cowboy scene?"
                },
                "provider": {
                    "type": "OKTA",
                    "name": "OKTA"
                }
            },
            "_links": {
                "resetPassword": {
                    "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/lifecycle/reset_password"
                },
                "resetFactors": {
                    "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/lifecycle/reset_factors"
                },
                "expirePassword": {
                    "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/lifecycle/expire_password"
                },
                "forgotPassword": {
                    "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/credentials/forgot_password"
                },
                "changeRecoveryQuestion": {
                    "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/credentials/change_recovery_question"
                },
                "deactivate": {
                    "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/lifecycle/deactivate"
                },
                "changePassword": {
                    "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/credentials/change_password"
                }
            }
        },
        'https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/factors': [
            {
                "id": "opfh52xcuft3J4uZc0g3",
                "factorType": "push",
                "provider": "OKTA",
                "vendorName": "OKTA",
                "status": "ACTIVE",
                "created": "2014-04-15T18:10:06.000Z",
                "lastUpdated": "2014-04-15T18:10:06.000Z",
                "_links": {
                    "poll": {
                        "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/factors/opfh52xcuft3J4uZc0g3/verify",
                        "hints": {
                            "allow": [
                                "GET"
                            ]
                        }
                    },
                    "self": {
                        "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/factors/opfh52xcuft3J4uZc0g3",
                        "hints": {
                            "allow": [
                                "GET",
                                "DELETE"
                            ]
                        }
                    },
                    "user": {
                        "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR",
                        "hints": {
                            "allow": [
                                "GET"
                            ]
                        }
                    }
                }
            }
        ],
        'https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors': [
            {
                "id": "ufs2bysphxKODSZKWVCT",
                "factorType": "question",
                "provider": "OKTA",
                "vendorName": "OKTA",
                "status": "ACTIVE",
                "created": "2014-04-15T18:10:06.000Z",
                "lastUpdated": "2014-04-15T18:10:06.000Z",
                "profile": {
                    "question": "favorite_art_piece",
                    "questionText": "What is your favorite piece of art?"
                },
                "_links": {
                    "questions": {
                        "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/questions",
                        "hints": {
                            "allow": [
                                "GET"
                            ]
                        }
                    },
                    "self": {
                        "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/ufs2bysphxKODSZKWVCT",
                        "hints": {
                            "allow": [
                                "GET",
                                "DELETE"
                            ]
                        }
                    },
                    "user": {
                        "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL",
                        "hints": {
                            "allow": [
                                "GET"
                            ]
                        }
                    }
                }
            },
            {
                "id": "ostf2gsyictRQDSGTDZE",
                "factorType": "token:software:totp",
                "provider": "OKTA",
                "status": "PENDING_ACTIVATION",
                "created": "2014-06-27T20:27:33.000Z",
                "lastUpdated": "2014-06-27T20:27:33.000Z",
                "profile": {
                    "credentialId": "dade.murphy@example.com"
                },
                "_links": {
                    "next": {
                        "name": "activate",
                        "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/ostf2gsyictRQDSGTDZE/lifecycle/activate",
                        "hints": {
                            "allow": [
                                "POST"
                            ]
                        }
                    },
                    "self": {
                        "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/ostf2gsyictRQDSGTDZE",
                        "hints": {
                            "allow": [
                                "GET"
                            ]
                        }
                    },
                    "user": {
                        "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL",
                        "hints": {
                            "allow": [
                                "GET"
                            ]
                        }
                    }
                },
                "_embedded": {
                    "activation": {
                        "timeStep": 30,
                        "sharedSecret": "HE64TMLL2IUZW2ZLB",
                        "encoding": "base32",
                        "keyLength": 16
                    }
                }
            },
            {
                "id": "sms2gt8gzgEBPUWBIFHN",
                "factorType": "sms",
                "provider": "OKTA",
                "status": "ACTIVE",
                "created": "2014-06-27T20:27:26.000Z",
                "lastUpdated": "2014-06-27T20:27:26.000Z",
                "profile": {
                    "phoneNumber": "+1-555-415-1337"
                },
                "_links": {
                    "verify": {
                        "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/sms2gt8gzgEBPUWBIFHN/verify",
                        "hints": {
                            "allow": [
                                "POST"
                            ]
                        }
                    },
                    "self": {
                        "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/sms2gt8gzgEBPUWBIFHN",
                        "hints": {
                            "allow": [
                                "GET",
                                "DELETE"
                            ]
                        }
                    },
                    "user": {
                        "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL",
                        "hints": {
                            "allow": [
                                "GET"
                            ]
                        }
                    }
                }
            }
        ],
        'https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/factors/opfh52xcuft3J4uZc0g3/verify': {
            "expiresAt": "2015-04-01T15:57:32.000Z",
            "factorResult": "WAITING",
            "_links": {
                "poll": {
                    "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/factors/opfh52xcuft3J4uZc0g3/transactions/mst1eiHghhPxf0yhp0g",
                    "hints": {
                        "allow": [
                            "GET"
                        ]
                    }
                },
                "cancel": {
                    "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/factors/opfh52xcuft3J4uZc0g3/transactions/mst1eiHghhPxf0yhp0g",
                    "hints": {
                        "allow": [
                            "DELETE"
                        ]
                    }
                }
            }
        },
        'https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR/factors/opfh52xcuft3J4uZc0g3/transactions/mst1eiHghhPxf0yhp0g': {
            "factorResult": "SUCCESS"
        },
        'https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/opfh52xcuft3J4uZc0g3/verify': {
            "expiresAt": "2015-04-01T15:57:32.000Z",
            "factorResult": "WAITING",
            "_links": {
                "poll": {
                    "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/opfh52xcuft3J4uZc0g3/transactions/mst1eiHghhPxf0yhp0g",
                    "hints": {
                        "allow": [
                            "GET"
                        ]
                    }
                },
                "cancel": {
                    "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/opfh52xcuft3J4uZc0g3/transactions/mst1eiHghhPxf0yhp0g",
                    "hints": {
                        "allow": [
                            "DELETE"
                        ]
                    }
                }
            }
        },
        'https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/opfh52xcuft3J4uZc0g3/transactions/mst1eiHghhPxf0yhp0g': {
            "factorResult": "REJECTED",
            "profile": {
                "credentialId": "jane.doe@example.com"
            },
            "_links": {
                "verify": {
                    "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/opfh52xcuft3J4uZc0g3/verify",
                    "hints": {
                        "allow": [
                            "POST"
                        ]
                    }
                },
                "factor": {
                    "href": "https://fake/api/v1/users/00u15s1KDETTQMQYABRL/factors/opfh52xcuft3J4uZc0g3",
                    "hints": {
                        "allow": [
                            "GET",
                            "DELETE"
                        ]
                    }
                }
            }
        },
        'https://fake/api/v1/users?search=profile.samAccountName%20eq%20%22username%22':
            [
                {
                    "id": "00ub0oNGTSWTBKOLGLNR",
                    "status": "ACTIVE",
                    "created": "2013-06-24T16:39:18.000Z",
                    "activated": "2013-06-24T16:39:19.000Z",
                    "statusChanged": "2013-06-24T16:39:19.000Z",
                    "lastLogin": "2013-06-24T17:39:19.000Z",
                    "lastUpdated": "2013-07-02T21:36:25.344Z",
                    "passwordChanged": "2013-07-02T21:36:25.344Z",
                    "profile": {
                        "firstName": "Eric",
                        "lastName": "Judy",
                        "email": "eric.judy@example.com",
                        "secondEmail": "eric@example.org",
                        "login": "eric.judy@example.com",
                        "mobilePhone": "555-415-2011"
                    },
                    "credentials": {
                        "password": {},
                        "recovery_question": {
                            "question": "The stars are projectors?"
                        },
                        "provider": {
                            "type": "OKTA",
                            "name": "OKTA"
                        }
                    },
                    "_links": {
                        "self": {
                            "href": "https://fake/api/v1/users/00ub0oNGTSWTBKOLGLNR"
                        }
                    }
                }
            ]

    }

    u = url_data.get(args[0])
    if u:
        return MockResponse(u, 200)

    return MockResponse(None, 404)


class TestOkta(unittest.TestCase):
    def setUp(self):
        self.okta = OktaAPI(url="fake", key="fake")

    @patch('requests.Session.get', side_effect=mocked_sessions)
    def test_get_user_id(self, mock_get):
        r = self.okta.get_user_id('isaac.brock@example.com')
        self.assertEqual(r, '00ub0oNGTSWTBKOLGLNR')

    @patch('requests.Session.get', side_effect=mocked_sessions)
    def test_get_user_push_factor_none(self, mock_get):
        user_id = '00u15s1KDETTQMQYABRL'
        r = self.okta.get_user_push_factor(user_id)

        self.assertIsNone(r)

    @patch('requests.Session.get', side_effect=mocked_sessions)
    @patch('requests.Session.post', side_effect=mocked_sessions)
    def test_push_verify_success(self, mock_get, mock_post):
        user_id = '00ub0oNGTSWTBKOLGLNR'
        factor_id = 'opfh52xcuft3J4uZc0g3'
        r = self.okta.push_verify(user_id, factor_id)

        self.assertEqual(r, ResponseCodes.SUCCESS)

    @patch('requests.Session.get', side_effect=mocked_sessions)
    @patch('requests.Session.post', side_effect=mocked_sessions)
    def test_push_verify_failure(self, mock_get, mock_post):
        user_id = '00u15s1KDETTQMQYABRL'
        factor_id = 'opfh52xcuft3J4uZc0g3'
        r = self.okta.push_verify(user_id, factor_id)

        self.assertEqual(r, ResponseCodes.FAILURE)

    @patch('requests.Session.get', side_effect=mocked_sessions)
    @patch('requests.Session.post', side_effect=mocked_sessions)
    def test_push_verify_double(self, mock_get, mock_post):
        user_id = '00ub0oNGTSWTBKOLGLNR'
        factor_id = 'opfh52xcuft3J4uZc0g3'
        r1 = self.okta.push_verify(user_id, factor_id)
        r2 = self.okta.push_verify(user_id, factor_id)

        self.assertEqual(r1, ResponseCodes.SUCCESS)
        self.assertEqual(r2, ResponseCodes.SUCCESS)


    @patch('requests.Session.get', side_effect=mocked_sessions)
    def test_get_user_by_samaccountname(self, mock_get):
        samAccountName = 'username'
        r = self.okta.get_user_by_samaccountname(samAccountName)

        self.assertEqual(r, '00ub0oNGTSWTBKOLGLNR')

        mock_get.assert_called_once_with('https://fake/api/v1/users?search=profile'
                                         '.samAccountName%20eq%20%22username%22', params=None)


class TestThreadTTLContextManager(unittest.TestCase):
    def setUp(self):
        self.thread_mgr = ThreadTTLContextManager()

    def t(self, num, q):
        q.put("SUCCESS")
        return

    def test_orig(self):
        thread = self.thread_mgr.get_or_create("fake", self.t, (1, ))
        thread2 = self.thread_mgr.get_or_create("fake", self.t, (2, ))
        self.assertEqual(thread, thread2)

    @patch('time.time')
    def test_time1(self, mock_time):
        mock_time.return_value = 1618000000
        thread = self.thread_mgr.get_or_create("fake", self.t, (1,))
        mock_time.return_value = 1618000060
        thread2 = self.thread_mgr.get_or_create("fake", self.t, (2,))
        self.assertEqual(thread, thread2)

    @patch('time.time')
    def test_time2(self, mock_time):
        mock_time.return_value = 1618000000
        thread = self.thread_mgr.get_or_create("fake", self.t, (1,))
        mock_time.return_value = 1618000100
        thread2 = self.thread_mgr.get_or_create("fake", self.t, (2,))
        self.assertNotEqual(thread, thread2)


class TestRadius(unittest.TestCase):
    def setUp(self):
        self.server = RadiusServer('fake', 'whatever')
        self.origsocket = socket.socket
        socket.socket = MockSocket

    def tearDown(self) -> None:
        socket.socket = self.origsocket

    @classmethod
    def setUpClass(cls) -> None:
        cls.env_patcher = patch.dict(os.environ, {
            "OKTA_TENANT": 'fake',
            "OKTA_API_KEY": 'fake',
            "RADIUS_SECRET": 'whatever'
        })
        cls.env_patcher.start()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        super().tearDownClass()
        cls.env_patcher.stop()

    def test_bind(self):
        self.server.hosts["192.168.123.123"] = os.getenv('RADIUS_SECRET')
        self.server.BindToAddress("192.168.123.123")

        self.assertEqual(len(self.server.authfds), 1)
        self.assertEqual(self.server.authfds[0].address, ('192.168.123.123', 1812))

    @patch('requests.Session.get', side_effect=mocked_sessions)
    @patch('requests.Session.post', side_effect=mocked_sessions)
    def test_success_okta(self, a, b):
        self.server.hosts["127.0.0.1"] = os.getenv('RADIUS_SECRET')
        self.server.BindToAddress("127.0.0.1")

        Client(server="127.0.0.1", secret=os.getenv('RADIUS_SECRET').encode(), dict=Dictionary("dictionary"))

        # create request
        req = AuthPacket(
            id=AccessRequest,
            secret=os.getenv('RADIUS_SECRET').encode(),
            authenticator=b'01234567890ABCDEF',
            dict=Dictionary("dictionary")
        )
        req["User-Name"] = 'isaac.brock@example.com'
        req["User-Password"] = req.PwCrypt('fake')
        req["Proxy-State"] = 'state'.encode("ascii")
        req.source = ("test", "port")
        fd = MockFd()
        req.fd = fd

        # send request
        with self.assertLogs('server', level='INFO') as log:
            self.server.auth_handler(req)
            self.assertEqual(fd.data, b'\x02\x01\x00\x1b\x82\xb4\x88\xb4G\xbc:\xde\xc1\xe5A\xe0\xe7y\r\x1f!\x07state')
            self.assertIn('INFO:server:Push approved by isaac.brock@example.com.', log.output)

    @patch('requests.Session.get', side_effect=mocked_sessions)
    @patch('requests.Session.post', side_effect=mocked_sessions)
    @patch('okta.OktaAPI.get_user_by_samaccountname')
    @patch.dict(os.environ, {'OKTA_USE_SAMACCOUNTNAME': 'true'})
    def test_using_samaccountname_flag(self, o, mock_get, mock_post):
        self.assertIsNotNone(os.environ.get('OKTA_USE_SAMACCOUNTNAME'))

        self.server.hosts["127.0.0.1"] = os.getenv('RADIUS_SECRET')
        self.server.BindToAddress("127.0.0.1")

        Client(server="127.0.0.1", secret=os.getenv('RADIUS_SECRET').encode(), dict=Dictionary("dictionary"))

        # create request
        req = AuthPacket(
            id=AccessRequest,
            secret=os.getenv('RADIUS_SECRET').encode(),
            authenticator=b'01234567890ABCDEF',
            dict=Dictionary("dictionary")
        )
        req["User-Name"] = 'username'
        req["User-Password"] = req.PwCrypt('fake')
        req["Proxy-State"] = 'state'.encode()
        req.source = ("test", "port")
        fd = MockFd()
        req.fd = fd

        # send request
        with self.assertLogs('server', level='INFO') as log:
            o.return_value = '00ub0oNGTSWTBKOLGLNR'
            self.server.auth_handler(req)
            o.assert_called_once_with('username')
            self.assertEqual(fd.data, b'\x02\x01\x00\x1b\x82\xb4\x88\xb4G\xbc:\xde\xc1\xe5A\xe0\xe7y\r\x1f!\x07state')
            self.assertIn('INFO:server:Push approved by username.', log.output)


    @patch.dict(os.environ, {}, clear=True)
    def test_without_env_set(self):
        with self.assertLogs('server', level='ERROR') as log:
            with self.assertRaises(SystemExit):
                runpy.run_module(run())

            self.assertIn('ERROR:server:Missing environment variables!', log.output)
