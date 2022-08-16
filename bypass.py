#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from time import sleep
from io import BytesIO
from threading import Thread
from random import getrandbits
from ipaddress import IPv4Address
from colorama import init

import json, requests
import random, certifi, os, pycurl

spinners = ["/", "-", "\\", "|"]
dir_path = os.path.dirname(os.path.realpath(__file__))

bad_responses = [
    "/challenge/", # Account is email/phone locked
    "consent_required", # Most likely GDPR
    "feedback_required", # Spamblock :(
    "login_required", # Expired/invalid/revoked session
    "nother account" # Fucked up fucked up fucked up
]

init()
RED = "\033[1;31;40m"
GREEN = "\033[1;32;40m"
BLUE = "\033[1;36;40m"
WHITE = "\033[1;37;40m"
MAGENTA = "\033[1;35;40m"
INPUT = "[\x1b[33m?\x1b[39m]"
INFO = "[\x1b[35m*\x1b[39m]"
Main1 = "\033[1;37;40m[\x1b[35mMain\033[1;37;40m\033[1;37;40m]"
SUCCESS = "\033[1;37;40m[\x1b[32mTurbo\033[1;37;40m\033[1;37;40m]"
console = "\033[1;37;40m[\x1b[35mTurbo\033[1;37;40m\033[1;37;40m]"
console1 = "\033[1;1;40m[\x1b[32mTurbo\033[1;37;40m\033[1;37;40m]"
console2 = "\033[1;1;40m[\x1b[33mTurbo\033[1;37;40m\033[1;37;40m]"
console3 = "\033[1;1;40m[\x1b[36mTurbo\033[1;37;40m\033[1;37;40m]"
console4 = "\033[1;1;40m[\x1b[37mTurbo\033[1;37;40m\033[1;37;40m]"
console5 = "\033[1;1;40m[\x1b[34mTurbo\033[1;37;40m\033[1;37;40m]"
ERROR = "\033[1;1;40m[\x1b[31mError\033[1;37;40m\033[1;37;40m]"
spinners1 = [console, console1, console2, console3, console4, console5]
SUCCESS1 = "\033[1;37;40m[\x1b[31mS\033[34mu\033[37mc\033[36mc\033[33me\033[35ms\033[32ms\033[1;37;40m\033[1;37;40m]"
TWIT_UA = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36"
csrfToken = "5a38ea9736c3658c40a94a9891cd763d"
IG_API_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=UTF-8"
authToken = "aa4b3ee760bab2a1aab7eb2b90f9a65da107d037"
authToken2 = "5a2375286f4b06927633724349750bf27f005d41"
bearerToken = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

def http_request(url, headers, data=None):
    curl = pycurl.Curl()
    response = b''
    curl.setopt(pycurl.URL, url)
    # curl.setopt(pycurl.WRITEDATA, response)
    curl.setopt(pycurl.ENCODING, "")
    curl.setopt(pycurl.HTTPHEADER, headers)
    if data:
        curl.setopt(pycurl.POST, True)
        curl.setopt(pycurl.POSTFIELDS, data)
    try:
        response = curl.perform_rb()
    except:
        pass
    return response.decode("utf-8")
def http_request2(url, headers, data=None, proxy=None):
    curl = pycurl.Curl()
    response = b''
    curl.setopt(pycurl.URL, url)
    # curl.setopt(pycurl.WRITEDATA, response)
    curl.setopt(pycurl.ENCODING, "")
    curl.setopt(pycurl.HTTPHEADER, headers)
    if proxy:
        curl.setopt(pycurl.PROXY, proxy)
        curl.setopt(pycurl.CONNECTTIMEOUT, 1)
        curl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_HTTP)
    try:
        response = curl.perform_rb()
    except:
        pass
    finally:
        curl.close()
    return response.decode("utf-8")
class twit_jr(object):
    def __init__(self):
        super(twit_jr, self).__init__()
        self.claimed = False
        self.running = True
        self.attempts = 0
        self.rl = 0
        self.rs = 0
        self.s = requests.Session()

    def claim_username1(self, target):
        response = http_request2("https://api.twitter.com/1.1/account/settings.json",[
            "Accept: */*",
            "User-Agent: " + TWIT_UA,
            "Content-Type: " "application/x-www-form-urlencoded",
            "Referer:  ""https://twitter.com/settings/screen_name",
            "X-CSRF-Token: " + csrfToken,
            "Authorization: " "Bearer " + bearerToken,
            "X-Remote-IP: " + str(IPv4Address(getrandbits(32))),
            "X-Forwarded-For: ",
            "Cookie: auth_token=" + authToken2 + "; ct0=" + csrfToken
            ], f"screen_name=tooth")
        if "Could not authenticate you." in response:
            print(f"\n{ERROR} Bad token.")
        else:
            print(f"\n{SUCCESS} Valid token.")
        
    def claim_username(self, target):
        response = http_request("https://api.twitter.com/1.1/account/settings.json",[
            "Accept: */*",
            "User-Agent: " + TWIT_UA,
            "Content-Type: " "application/x-www-form-urlencoded",
            "Referer:  ""https://twitter.com/settings/screen_name",
            "X-CSRF-Token: " + csrfToken,
            "Authorization: " "Bearer " + bearerToken,
            "Cookie: auth_token=" + authToken2 + "; ct0=" + csrfToken
        ], "screen_name=" + target)
        #print(response)
        if not response:
            return False
        elif f'"screen_name":"{target}"' in response:
            self.yup = target
            return True


class Turbo(Thread):
    def __init__(self, twit_jr, target):
        super(Turbo, self).__init__()
        self.twit_jr = twit_jr
        self.target = target

    def _setTwitterConnection(self):
        try:
            self._conn = pycurl.Curl()
            self._conn.setopt(pycurl.ENCODING, 'gzip')
            self._conn.setopt(pycurl.SSL_VERIFYPEER, 0)
            self._conn.setopt(pycurl.SSL_VERIFYHOST, 0)
            self._conn.setopt(pycurl.TIMEOUT, 1)
            self._conn.setopt(curl.NOSIGNAL, 500)
            return self._conn
        except: pass

    def _getTwitterResponse(self, url):
        while True:
            try:
                self._conn.setopt(pycurl.URL, url)
                self._conn.setopt(pycurl.HTTPHEADER, ["X-CSRF-Token: 83368f29e6d092aacef9e4b10b0185ab", 
                "Authorization: Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"])
                response = self._conn.perform_rs()
                if 'Sorry, that page does not exist.' in response:
                    return True
                else:
                    self.twit_jr.attempts += 1
            except:
                self._conn.close()
                self._setTwitterConnection()
                pass

    def run(self):
        self._setTwitterConnection()
        while self.twit_jr.running:
                    if self._getTwitterResponse('https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name=%s&count=1&max_id=0' % target):
                        if self.twit_jr.claim_username(self.target):
                            self.twit_jr.claimed = True
                            self.twit_jr.running = False

                        sleep(0.001)

class RequestsPS(Thread):
    def __init__(self, twit_jr):
        super(RequestsPS, self).__init__()
        self.twit_jr = twit_jr

    def run(self):
        while self.twit_jr.running:
            before = self.twit_jr.attempts
            sleep(1) # Wait 1 second, calculate the difference
            self.twit_jr.rs = self.twit_jr.attempts - before

if __name__ == "__main__":
    twit_jr = twit_jr()
    authToken2 = input(f"{Main1}{WHITE} Auth Token: ")
    threads = int(input("{} Threads: ".format(Main1)))
    target = input("{} Target: ".format(Main1)).strip().lower()
    twit_jr.claim_username1(target)

    for _ in range(threads):
        thread = Turbo(twit_jr, target)
        thread.setDaemon(True)
        thread.start()

    rs_thread = RequestsPS(twit_jr)
    rs_thread.setDaemon(True)
    rs_thread.start()

    print("\n{} All threads successfully initialized".format(SUCCESS))

    try:
        while twit_jr.running:
            for spinner in spinners1:
                print("{} {:,} attempts | RateLimit: {:,} | Reqs Per Second: {:,}{}".format(spinner, twit_jr.attempts, twit_jr.rl,twit_jr.rs, " " * 10), end="\r", flush=True)
                sleep(0.075)  # Update attempts every 100ms
    except KeyboardInterrupt:
        twit_jr.running = False
        print("\n\r{} Turbo stopped, exiting after {:,} attempts...".format(ERROR, twit_jr.attempts))
        pass

    if twit_jr.claimed:
        print("\r{} Claimed username \x1b[32m@{}\x1b[37m after \x1b[32m{:,}\x1b[37m attempts \n".format(SUCCESS, target, twit_jr.attempts + 1))

    sleep(0.1)
    pycurl.global_cleanup()
