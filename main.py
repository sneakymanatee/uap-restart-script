import json
import logging
import sys
import time
from logging.handlers import RotatingFileHandler

import click
import requests
from requests import Session
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logging.getLogger().setLevel(logging.INFO)
logging_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

stdOutHandler = logging.StreamHandler(sys.stdout)
stdOutHandler.setFormatter(logging_format)
logging.getLogger().addHandler(stdOutHandler)

fileHandler = RotatingFileHandler("uap-restart.log", maxBytes=(1048576 * 5), backupCount=7)
fileHandler.setFormatter(logging_format)
logging.getLogger().addHandler(fileHandler)


def login(host: str, username: str, password: str, session: Session):
    url = f"https://{host}/api/auth/login"

    payload = json.dumps({
        "username": username,
        "password": password,
        "token": "",
        "rememberMe": False
    })

    headers = {
        'content-type': 'application/json',
    }
    response = session.request("POST", url, headers=headers, data=payload, verify=False)

    logging.debug(response.text)
    logging.debug(response.headers)
    logging.debug(session.cookies)
    session.headers['x-csrf-token'] = response.headers['x-csrf-token']
    logging.debug(session.headers)


def get_uap(host: str, session: Session):
    url = f"https://{host}/proxy/network/v2/api/site/default/device"

    payload = {}
    headers = {
        'accept': 'application/json, text/plain, */*',
    }

    response = session.request("GET", url, headers=headers, data=payload, verify=False)
    data = response.json()
    mac = []

    for device in data['network_devices']:
        if device['type'] == 'uap':
            mac.append(device['mac'])

    for item in mac:
        logging.info(item)
    return mac


def restart_uap(host: str, mac_address: str, session):
    logging.info(f"Restart device {mac_address}")
    url = f"https://{host}/proxy/network/api/s/default/cmd/devmgr"

    payload = json.dumps({
        "mac": mac_address,
        "reboot_type": "soft",
        "cmd": "restart"
    })
    headers = {
        'content-type': 'application/json',
        'x-csrf-token': session.headers['x-csrf-token']
    }

    response = session.request("POST", url, headers=headers, data=payload, verify=False)

    logging.info(response.text)


@click.command()
@click.option('--host', prompt="Unifi controller host", help='Host IP or domain of the unifi controller')
@click.option('--username', prompt='Your name', help='Username')
@click.option('--password', prompt='Your password', help='Password')
def run(host: str, username: str, password: str):
    session = requests.session()
    login(host=host, username=username, password=password, session=session)
    mac_addresses = get_uap(host=host, session=session)

    for mac_address in mac_addresses:
        restart_uap(host=host, mac_address=mac_address, session=session)
        time.sleep(60 * 2)


if __name__ == '__main__':
    logging.info("Start")
    run()
    logging.info("End")
