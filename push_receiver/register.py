import os
import time
import json
import base64
import secrets
import logging
import requests
from .mcs import *
from base64 import urlsafe_b64encode
from oscrypto.asymmetric import generate_pair
from urllib.request import Request, urlopen
from urllib.parse import urlencode

unicode = str
REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
CHECKIN_URL = "https://android.clients.google.com/checkin"
FIREBASE_INSTALLATION = 'https://firebaseinstallations.googleapis.com/v1'
FCM_REGISTRATION = 'https://fcmregistrations.googleapis.com/v1'
FCM_ENDPOINT = 'https://fcm.googleapis.com/fcm/send'

SERVER_KEY = (
        b"\x04\x33\x94\xf7\xdf\xa1\xeb\xb1\xdc\x03\xa2\x5e\x15\x71\xdb\x48\xd3"
        + b"\x2e\xed\xed\xb2\x34\xdb\xb7\x47\x3a\x0c\x8f\xc4\xcc\xe1\x6f\x3c"
        + b"\x8c\x84\xdf\xab\xb6\x66\x3e\xf2\x0c\xd4\x8b\xfe\xe3\xf9\x76\x2f"
        + b"\x14\x1c\x63\x08\x6a\x6f\x2d\xb1\x1a\x95\xb0\xce\x37\xc0\x9c\x6e"
)

__log = logging.getLogger("push_receiver")

API_KEY = "AIzaSyB5y2y-Tzqb4-I4Qnlsh_9naYv_TD8pCvY"
APP_ID = "1:976529667804:android:d6f1ddeb4403b338fea619"
PROJECT_ID = "rust-companion-app"


def __generate_firebase_fid():
    # A valid FID has exactly 22 base64 characters, which is 132 bits, or 16.5
    # bytes. Our implementation generates a 17 byte array instead.
    fid = bytearray(secrets.token_bytes(17))

    # Replace the first 4 random bits with the constant FID header of 0b0111.
    fid[0] = 0b01110000 + (fid[0] % 0b00010000)

    return base64.b64encode(fid).decode('utf-8')


def __install_fcm():
    headers = {
        'x-firebase-client': base64.b64encode(json.dumps({'heartbeats': [], 'version': 2}).encode('utf-8')).decode(
            'utf-8'),
        'x-goog-api-key': API_KEY
    }
    data = {
        'appId': APP_ID,
        'authVersion': 'FIS_v2',
        'fid': __generate_firebase_fid(),
        'sdkVersion': 'w:0.6.4'
    }
    url = f"{FIREBASE_INSTALLATION}/projects/{PROJECT_ID}/installations"

    response = requests.post(url, headers=headers, json=data)
    return response.json()


def __do_request(req, retries=5):
    for _ in range(retries):
        try:
            resp = urlopen(req)
            resp_data = resp.read()
            resp.close()
            return resp_data
        except Exception as e:
            __log.warn("error during request", exc_info=e)
            time.sleep(1)
    return None


def gcm_check_in(android_id=None, security_token=None, **kwargs):
    """
  perform check-in request

  androidId, securityToken can be provided if we already did the initial
  check-in

  returns dict with androidId, securityToken and more
  """
    chrome = ChromeBuildProto()
    chrome.platform = 3
    chrome.chrome_version = "63.0.3234.0"
    chrome.channel = 1

    checkin = AndroidCheckinProto()
    checkin.type = 3
    checkin.chrome_build = chrome

    payload = AndroidCheckinRequest()
    payload.user_serial_number = 0
    payload.checkin = checkin
    payload.version = 3
    if android_id:
        payload.id = int(android_id)
    if security_token:
        payload.security_token = int(security_token)

    __log.debug(f'GCM check in payload:\n{payload}')
    req = Request(
        url=CHECKIN_URL,
        headers={"Content-Type": "application/x-protobuf"},
        data=payload.SerializeToString()
    )
    resp_data = __do_request(req)
    resp = AndroidCheckinResponse()
    resp.parse(resp_data)
    __log.debug(f'GCM check in response (raw):\n{resp}')
    return resp.to_dict()


def urlsafe_base64(data):
    """
  base64-encodes data with -_ instead of +/ and removes all = padding.
  also strips newlines

  returns a string
  """
    res = urlsafe_b64encode(data).replace(b"=", b"")
    return res.replace(b"\n", b"").decode("ascii")


def gcm_register(appId, retries=5, **kwargs):
    """
  obtains a gcm token

  appId: app id as an integer
  retries: number of failed requests before giving up

  returns {"token": "...", "appId": 123123, "androidId":123123,
           "securityToken": 123123}
  """
    # contains androidId, securityToken and more
    chk = gcm_check_in()
    __log.debug(f'GCM check in response {chk}')
    body = {
        "app": "org.chromium.linux",
        "X-subtype": appId,
        "device": chk["androidId"],
        "sender": urlsafe_base64(SERVER_KEY)
    }
    data = urlencode(body)
    __log.debug(f'GCM Registration request: {data}')
    auth = "AidLogin {}:{}".format(chk["androidId"], chk["securityToken"])
    req = Request(
        url=REGISTER_URL,
        headers={"Authorization": auth},
        data=data.encode("utf-8")
    )
    for _ in range(retries):
        resp_data = __do_request(req, retries)
        if b"Error" in resp_data:
            err = resp_data.decode("utf-8")
            __log.error("Register request has failed with " + err)
            time.sleep(1)
            continue
        token = resp_data.decode("utf-8").split("=")[1]
        chkfields = {k: chk[k] for k in ["androidId", "securityToken"]}
        res = {"token": token, "appId": appId}
        res.update(chkfields)
        return res
    return None


def fcm_register(sender_id, token, retries=5):
    """
  generates key pair and obtains a fcm token

  sender_id: sender id as an integer
  token: the subscription token in the dict returned by gcm_register

  returns {"keys": keys, "fcm": {...}}
  """
    # I used this analyzer to figure out how to slice the asn1 structs
    # https://lapo.it/asn1js
    # first byte of public key is skipped for some reason
    # maybe it's always zero
    public, private = generate_pair("ec", curve=unicode("secp256r1"))
    from base64 import b64encode
    __log.debug(f"# public: {b64encode(public.asn1.dump())}")
    __log.debug(f"# private: {b64encode(private.asn1.dump())}")
    keys = {
        "public": urlsafe_base64(public.asn1.dump()[26:]),
        "private": urlsafe_base64(private.asn1.dump()),
        "secret": urlsafe_base64(os.urandom(16))
    }
    data = {
        "web": {
            "applicationPubKey": "",
            "auth": keys["secret"],
            "p256dh": keys["public"],
            "endpoint": f"{FCM_ENDPOINT}/{token}"
        }
    }

    installation = __install_fcm()
    headers = {
        "Content-Type": "application/json",
        'x-goog-api-key': API_KEY,
        'x-goog-firebase-installations-auth': installation["authToken"]["token"]
    }
    __log.debug(f'FCM registration data: {data}')
    req = Request(url=f"{FCM_REGISTRATION}/projects/{PROJECT_ID}/registrations", data=json.dumps(data).encode("utf-8"),
                  headers=headers)

    resp_data = __do_request(req, retries)
    return {"keys": keys, "fcm": json.loads(resp_data.decode("utf-8"))}


def register(sender_id, app_id):
    """register gcm and fcm tokens for sender_id"""
    subscription = gcm_register(appId=app_id)
    if subscription is None:
        raise Exception("Unable to establish subscription with Google Cloud Messaging.")
    __log.debug(f'GCM subscription: {subscription}')
    fcm = fcm_register(sender_id=sender_id, token=subscription["token"])
    __log.debug(f'FCM registration: {fcm}')
    res = {"gcm": subscription}
    res.update(fcm)
    return res
