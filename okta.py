import logging

from requests import Session
from requests.compat import urljoin, urlencode, quote
from requests.exceptions import HTTPError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
import queue
import time

logger = logging.getLogger(__file__)


def error_handler(resp, *args, **kargs):
    if not resp.ok:
        raise HTTPError(resp.status_code, resp.json(), response=resp)


class ResponseCodes:
    SUCCESS = 1
    FAILURE = 2


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
        data = urlencode({'search': f"profile.samaccountname eq \"{username}\""}, quote_via=quote)
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

    def poll_verify(self, url, q):
        t = 0
        while True:
            page = self._get(url)

            if page["factorResult"] == "SUCCESS":
                q.put("SUCCESS")
                return
            elif page["factorResult"] == "REJECTED":
                q.put("FAILED")
                return

            time.sleep(4)
            t += 4

            if t > 60:
                return

    def push_verify(self, user_id, factor_id):
        url = urljoin(self.base_url, 'api/v1/users/{}/factors/{}/verify'.format(user_id, factor_id))

        page = self._post(url)

        poll_url = page["_links"]["poll"]["href"]

        q = queue.Queue()
        thread = threading.Thread(target=self.poll_verify, args=(poll_url, q))
        thread.start()
        thread.join()

        if q.qsize() > 0:
            if q.get() == "SUCCESS":
                return ResponseCodes.SUCCESS

        return ResponseCodes.FAILURE

