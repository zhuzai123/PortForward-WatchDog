# -*- coding: utf-8 -*-
#!/usr/bin/python3

import time
import json
import requests
import socket
from pathlib import Path

def get_configuration():
    config_path = Path("config.json")
    document = json.loads(source_path.read_text())
    
    # print(document)
    # print(type(document))

def check_port():
    pass

def update():
    pass

def Cloudflare_api():
    pass

if __name__ == '__main__':
    while(1):
        print('1')
        get_configuration()
        check_port()
        update()
        time.sleep(120)
        
