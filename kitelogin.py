import pyotp
import json
import requests
from kiteconnect import KiteConnect
from credentials_zerodha import USERNAME, PASSWORD, API_SECRET, API_KEY, TOTP_TOKEN
from api_urls import LOGIN_URL, TWOFA_URL

def autologin_zerodha():
    # Create a session
    session = requests.Session()
    # Step 1: Login with user_id and password
    response = session.post(LOGIN_URL, data={'user_id': USERNAME, 'password': PASSWORD})
    request_id = json.loads(response.text)['data']['request_id']

    # Step 2: Two factor authentication
    twofa_pin = pyotp.TOTP(TOTP_TOKEN).now()
    response_1 = session.post(
        TWOFA_URL,
        data={
            'user_id': USERNAME,
            'request_id': request_id,
            'twofa_value': twofa_pin,
            'twofa_type': 'totp'
        }
    )

    # Step 3: Get request_token from redirected URL after login
    kite = KiteConnect(api_key=API_KEY)
    kite_url = kite.login_url()
    print("[INFO] Kite login URL:", kite_url)

    try:
        session.get(kite_url)
    except Exception as e:
        e_msg = str(e)
        #print("[INFO] Exception message:", e_msg)
        if 'request_token=' in e_msg:
            request_token = e_msg.split('request_token=')[1].split(' ')[0].split('&action')[0]
            print('[INFO] Successful Login with Request Token: {}'.format(request_token))
            access_token = kite.generate_session(request_token, API_SECRET)['access_token']
            kite.set_access_token(access_token)
            return kite, access_token
        else:
            print('[ERROR] Could not extract request_token from exception.')
            return None

if __name__ == "__main__":
    result = autologin_zerodha()
    if result is not None:
        kite, access_token = result
        profile = kite.profile()
        print("Kite Profile:", profile)
    else:
        print("[ERROR] Login failed. Could not retrieve kite object or access token.")
# Yes, this is the correct approach for automating Kite login using TOTP and extracting the request_token from the redirected URL/exception, then generating the access token for API usage.

