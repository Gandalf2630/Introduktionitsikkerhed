#!/usr/bin/env python3
import requests
import json
import argparse
import getpass
import sys
import time
import urllib3

# Silence insecure request warnings since verify=False is used in the original script
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NessusClient:
    def __init__(self, nessusServer, nessusPort):
        self.nessusServer = nessusServer
        self.nessusPort = nessusPort
        self.url = 'https://' + str(nessusServer) + ':' + str(nessusPort)
        self.token = None
        self.headers = {}
        self.bodyRequest = {}

    def get_request(self, url):
        try:
            response = requests.get(url, params=self.bodyRequest or None, headers=self.headers, verify=False, timeout=15)
            response.raise_for_status()
            try:
                return response.json()
            except ValueError:
                return response.text
        except requests.RequestException as e:
            print("GET request failed:", e)
            # If the response object exists, try to return its text for debugging
            if hasattr(e, 'response') and e.response is not None:
                try:
                    return e.response.text
                except Exception:
                    pass
            return {}

    def post_request(self, url):
        try:
            response = requests.post(url, data=self.bodyRequest, headers=self.headers, verify=False, timeout=15)
            response.raise_for_status()
            try:
                return response.json()
            except ValueError:
                return response.text
        except requests.RequestException as e:
            # If the server returned a body (e.g. 401 with json), try to show it for debugging
            if hasattr(e, 'response') and e.response is not None:
                try:
                    print("Response body:", e.response.text)
                except Exception:
                    pass
            print("POST request failed:", e)
            return {}

    def request_api(self, service, params=None):
        # build headers; include token only if present
        self.headers = {
            'Host': f'{self.nessusServer}:{self.nessusPort}',
            'Content-type': 'application/x-www-form-urlencoded'
        }
        if self.token:
            self.headers['X-Cookie'] = 'token=' + self.token
        # optionally allow GET query params
        self.bodyRequest = params or {}
        content = self.get_request(self.url + service)
        return content

    def login(self, nessusUser, nessusPassword):
        headers = {
            'Host': f'{self.nessusServer}:{self.nessusPort}',
            'Content-type': 'application/x-www-form-urlencoded'
        }
        params = {'username': nessusUser, 'password': nessusPassword}
        self.bodyRequest.update(params)
        self.headers.update(headers)
        content = self.post_request(self.url + "/session")
        if isinstance(content, dict) and "token" in content:
            self.token = content['token']
        return content


def wait_until_ready(client, timeout=300, interval=5):
    """
    Poll /server/status until Nessus reports ready or until timeout.
    Returns the last status object (dict) received.
    """
    start = time.time()
    while True:
        status = client.request_api('/server/status')
        if not isinstance(status, dict):
            print("Unexpected /server/status response:", status)
            return status

        detail = status.get('detailed_status', {})
        db_status = detail.get('db_status', {}).get('status') if isinstance(detail, dict) else None
        engine_status = detail.get('engine_status', {}).get('status') if isinstance(detail, dict) else None
        feed = detail.get('feed_status', {}).get('status') if isinstance(detail, dict) else None
        top_status = status.get('status')

        print(f"server status: {top_status}  feed: {feed}  db: {db_status}  engine: {engine_status}")

        if top_status == 'ready' or db_status == 'ready':
            return status

        if time.time() - start > timeout:
            print(f"Timed out waiting for Nessus to become ready (timeout={timeout}s)")
            return status

        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', help='Nessus username')
    parser.add_argument('--password', help='Nessus password (omit to be prompted)')
    parser.add_argument('--host', default='127.0.0.1', help='Nessus server address (default: 127.0.0.1)')
    parser.add_argument('--port', default='8834', help='Nessus server port (default: 8834)')
    parser.add_argument('--wait', action='store_true', help='Wait for Nessus to finish initializing (poll /server/status)')
    parser.add_argument('--wait-timeout', type=int, default=300, help='Seconds to wait for initialization when --wait is set (default 300)')
    args = parser.parse_args()

    user = args.user
    password = args.password

    if not user:
        try:
            user = input("Nessus username: ")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)

    if password is None:
        try:
            password = getpass.getpass("Nessus password: ")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)

    client = NessusClient(args.host, args.port)
    login_response = client.login(user, password)
    if not isinstance(login_response, dict) or 'token' not in login_response:
        print("Login failed or unexpected response:", login_response)
        sys.exit(1)

    if args.wait:
        print("Waiting for Nessus to become ready (this may take a few minutes)...")
        status = wait_until_ready(client, timeout=args.wait_timeout)
    else:
        status = client.request_api('/server/status')

    print("Server status:")
    print(status)

    # Retrieve scans and handle all possible responses robustly
    scans_resp = client.request_api('/scans')

    # Debug: show raw scans response type/preview
    if isinstance(scans_resp, dict):
        # typical happy path: {'scans': [...]}
        scans = scans_resp.get('scans') or []
    else:
        # could be string, empty, or unexpected JSON
        print("Unexpected /scans response (not a JSON object):", repr(scans_resp))
        scans = []

    if not scans:
        print("No scans found. The server may be initializing or there are no scans configured.")
        print("If you believe there should be scans, verify in the web UI or try again later.")
        return

    print("Found scans:", scans)

    for scan in scans:
        if not isinstance(scan, dict):
            continue
        scan_id = scan.get('id')
        if not scan_id:
            continue
        scan_detail = client.request_api('/scans/' + str(scan_id))
        vulnerabilities = []
        if isinstance(scan_detail, dict):
            # older Nessus returns vuln lists under 'vulnerabilities' or 'hosts'
            vulnerabilities = scan_detail.get('vulnerabilities') or scan_detail.get('hosts') or []
        if not vulnerabilities:
            print(f"No vulnerabilities found for scan id {scan_id}")
            continue
        for vuln in vulnerabilities:
            # If vuln is a dict, try to print common fields
            if isinstance(vuln, dict):
                print(vuln.get('plugin_family'), vuln.get('plugin_name'))
            else:
                print(repr(vuln))


if __name__ == "__main__":
    main()