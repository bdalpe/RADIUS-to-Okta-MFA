import logging

from requests import Session
from requests.compat import urljoin, urlencode, quote
from requests.exceptions import HTTPError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
import queue
from queue import Empty
import time
import os

logger = logging.getLogger(__file__)


def error_handler(resp, *args, **kargs):
    if not resp.ok:
        raise HTTPError(resp.status_code, resp.json(), response=resp)


class ResponseCodes:
    SUCCESS = 1
    FAILURE = 2


class ThreadTTLContextManager:
    """
    Implements an "expiring" dict to handle outstanding requests to Okta.

    Each dict per username holds a queue, thread, result, and TTL.
    """
    def __init__(self):
        self.threads = {}
        self.lock = threading.Lock()

    def get_or_create(self, username, target, args):
        self.lock.acquire()
        if self.threads.get(username) and self.threads.get(username)['ttl'] >= time.time():
            self.lock.release()
            logger.debug(f"Reusing thread for {username}")
            return self.threads.get(username)['thread']
        else:
            q = queue.Queue()
            self.threads[username] = {
                'queue': q,
                'thread': threading.Thread(target=target, args=args + (q, )),
                'result': None,
                'ttl': time.time() + os.getenv("OKTA_POLL_TIMEOUT", 60)
            }
            logger.debug(f"Starting new thread for {username}")
            self.threads[username]['thread'].start()
            self.lock.release()
            return self.threads[username]['thread']

    def is_success(self, username):
        try:
            if self.threads[username]['result'] == 'SUCCESS' or self.threads.get(username)['queue'].get(block=False) == "SUCCESS":
                self.threads[username]['result'] = 'SUCCESS'
                return True
        except Empty:
            return False


class OktaAPI(object):
    def __init__(self, url, key):
        # Sessions are stateless
        self.base_url = "https://{}".format(url)
        self.key = key

        # Retry with backoff in case we get rate limited, otherwise use the error handler
        retry = Retry(total=3, backoff_factor=5, status_forcelist=[429])
        adapter = HTTPAdapter(max_retries=retry)

        session = Session()
        session.headers['Authorization'] = 'SSWS {}'.format(self.key)
        session.headers['Accept'] = 'application/json'
        session.headers['User-Agent'] = 'pyrad/1.0'
        session.hooks = {'response': [error_handler, ]}
        session.mount('https://', adapter)

        self.session = session
        self.thread_mgr = ThreadTTLContextManager()

    def _get(self, url, params=None):
        r = self.session.get(url, params=params)

        return r.json()

    def _post(self, url, params=None, json=None):
        r = self.session.post(url, params=params, json=json)

        return r.json()

    def get_user_id(self, username):
        url = urljoin(self.base_url, 'api/v1/users/{}'.format(username))

        page = self._get(url)

        return page["id"]

    def get_user_by_samaccountname(self, username):
        data = urlencode({'search': f"profile.samAccountName eq \"{username}\""}, quote_via=quote)
        url = urljoin(self.base_url, f"api/v1/users?{data}")

        page = self._get(url)

        return page[0]["id"]

    def get_user_push_factor(self, user_id):
        url = urljoin(self.base_url, 'api/v1/users/{}/factors'.format(user_id))

        page = self._get(url)

        # Return the first push factorType in the array, otherwise return None (no factor setup)
        try:
            return next(item for item in page if item["factorType"] == "push")
        except StopIteration:
            return None

    def poll_verify(self, user_id, factor_id, q):
        url = urljoin(self.base_url, 'api/v1/users/{}/factors/{}/verify'.format(user_id, factor_id))

        logger.debug(f"Sending push notification for {user_id} (Factor: {factor_id})")
        page = self._post(url)

        poll_url = page["_links"]["poll"]["href"]

        t = 0
        while True:
            page = self._get(poll_url)

            if page["factorResult"] == "SUCCESS":
                logger.debug(f"Push approved for {user_id}")
                q.put("SUCCESS")
                return
            elif page["factorResult"] == "REJECTED":
                logger.debug(f"Push rejected for {user_id}")
                q.put("FAILED")
                return

            time.sleep(4)
            t += 4

            if t > os.getenv("OKTA_POLL_TIMEOUT", 60):
                logger.debug(f"Push timed out for {user_id}")
                return

    def push_verify(self, user_id, factor_id):
        polling_thread = self.thread_mgr.get_or_create(user_id, self.poll_verify, (user_id, factor_id, ))
        polling_thread.join()

        if self.thread_mgr.is_success(user_id):
            return ResponseCodes.SUCCESS

        return ResponseCodes.FAILURE
