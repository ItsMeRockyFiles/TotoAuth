import time
import math
import hashlib
import hmac
import base64
import json
import uuid
import os

key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

def GetTotp(key:str):
    secret_key = base64.b32decode(key)

    t = time.time()
    t0 = 0

    ct = math.floor((t - t0) / 30)

    c = ct.to_bytes(8, byteorder="big", signed=False)

    hmac_sha1 = hmac.new(secret_key,c,hashlib.sha1).digest()

    offset = hmac_sha1[-1] & 0x0F

    slice_4bytes = hmac_sha1[offset:offset + 4]

    intvalue = ((slice_4bytes[0] & 0x7F) << 24) | (slice_4bytes[1] << 16) | (slice_4bytes[2] << 8) | (slice_4bytes[3])

    moduloIntValue = intvalue % 1000000

    TOTP = str(moduloIntValue).zfill(6)
    return TOTP

def load_accounts():
    if not os.path.exists(".accounts.json"):
        return []
    with open(".accounts.json", "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_accounts(accounts):
    with open(".accounts.json", "w") as f:
        json.dump(accounts, f, indent=2)

def CreateTotp(username, key, platform):
    accounts = load_accounts()
    accounts.append({
        "id": str(uuid.uuid4()),
        "username": username,
        "key": key,
        "platform": platform,
    })
    save_accounts(accounts)

print(GetTotp(key))