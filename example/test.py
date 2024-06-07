# Assume that this is the client

import requests, time, hmac

url = "http://localhost:5173"

endpoint = "/spam_intolerance_endpoint"
shared_key = b"Some not-so-secret key"

# Unsigned
r = requests.get(url=f'{url}{endpoint}')
assert r.status_code == 400
print(r.content)

# Signed
ts = str(int(time.time()))
headers = {
    "X-Timestamp": ts,
    "X-Signature": hmac.new(shared_key, ts.encode(), "sha512").hexdigest()
}
r = requests.get(url=f'{url}{endpoint}', headers=headers)
assert r.status_code == 200
print(r.content)