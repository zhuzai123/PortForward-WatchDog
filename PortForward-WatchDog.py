# -*- coding: utf-8 -*-
#!/usr/bin/python3

import re
import time
import json
import threading
import requests
import socket
import dns.resolver
from pathlib import Path

# DEFAULT CONFIG:
dns_server = '8.8.8.8'
debug = False
proxies = {}

def get_configuration():
    global dns_server, debug, proxies
    
    print('Start getting configuration.')
    config_path = Path('config.json')
    config = json.loads(config_path.read_text())

    target = config['target']
    for target_num in range(len(target)):
        target[target_num]['cname_address'].sort(key=lambda m: m['metric'])
        target[target_num]['check_interval'] = target[target_num].get('check_interval', 60) # Default check_interval
        target[target_num]['timeout'] = target[target_num].get('timeout', 2) # Default timeout
        target[target_num]['error_times'] = target[target_num].get('error_times', 3) # Default error_times
        target[target_num]['error_recheck_interval'] = target[target_num].get('error_recheck_interval', 3) # Default error_recheck_interval
        for cname_num in range(len(target[target_num]['cname_address'])):
            target[target_num]['cname_address'][cname_num]['metric'] = \
                target[target_num]['cname_address'][cname_num].get('metric', 100) # Default metric

    dns_server = config.get('dns_server', dns_server)
    debug = config.get('debug', debug)
    print('DNS Server: ' + str(dns_server))
    print('DEBUG: ' + str(debug) + '\n')
    proxies = config.get('proxies', proxies)

    return target, proxies

def start(trd_num, target, proxies):
    log_prefix = lambda :time.strftime("%y-%m-%d %H:%M:%S", time.localtime()) + ' Thread NO.' + str(trd_num +1) + ' ' + target['name'] + ' '
    print(log_prefix() + 'Starting...\n')
    print(log_prefix() + 'config ' + '\n' + str(target) + '\n' + '-' * 60 + '\n')
    target['api']['zone_id'] = target['api']['dns_record_id'] = ''
    while(1):
        for cname in target['cname_address']:
            for times in range(target['error_times']):
                if cname['method'] == 'tcp':
                    accessable, ip, latency = check_port(cname['address'], cname['method'], cname['port'], target['timeout'])
                    print(log_prefix() + cname['address'] + '(' + ip + '):' + str(cname['port']) + ' ', end='')
                    print('latancy: ' + str(latency) + 'ms.' if accessable else 'inaccessable. Retry: ' + str(times + 1) + '.')
                elif cname['method'] == 'icmp':
                    pass
                if accessable == 1:
                    target['api'], res = update(target['forward_address'], cname['address'], target['api'], proxies)
                    if res:
                        print(log_prefix() + res)
                    break
                time.sleep(target['error_recheck_interval'])
            if accessable == 1:
                break
        print(log_prefix() + 'waiting ' + str(target['check_interval']) + ' second(s).')
        time.sleep(target['check_interval'])

def check_port(address, method, port=65536, timeout=2):
    ip = '0.0.0.0'
    if re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$').match(address):
        ip = address
    else:
        try:
            dns_resolver = dns.resolver.Resolver()
            dns_resolver.nameservers = [dns_server]
            dns_resolver.timeout = 6

            dnsresolve = dns_resolver.resolve(address, 'A')
            for dns_response in dnsresolve.response.answer:
                for dns_answer in dns_response:
                    if type(dns_answer) == dns.rdtypes.IN.A.A:
                        ip = str(dns_answer)
        except:
            return False, ip, timeout * 1000

    if method == 'tcp':
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(timeout)
        try:
            t1 = time.time()
            sk.connect((ip, port))
            t2 = time.time()
            sk.close()
            return True, ip, int(round((t2-t1)*1000))
        except:
            sk.close()
            return False, ip, timeout * 1000

    elif method == 'icmp':
        return True, ip, 0

def update(forward_address, cname_addess, api, proxies):
    except_times = 0
    while(1):
        try:
            need_to_update = success = False
            res = 'No api in config.'
            if api['provider'] == 'Cloudflare':
                need_to_update, success, res ,api = cloudflare_api(api, forward_address, cname_addess)
            if need_to_update == success == 1:
                return api, '\nUpdate ' + forward_address + ' to ' + cname_addess + ' through ' + api['provider'] + ' successfully. Result:\n' + str(res) + '\n'
            elif need_to_update == 1:
                return api, '\nFailed to update ' + forward_address + ' to ' + cname_addess + ' through ' + api['provider'] + '. Result:\n' + str(res) + '\n'
            elif success == 1:
                return api, ''
            else:
                return api, '\nFailed to check ' + forward_address + ' record through ' + api['provider'] + '. Result:\n' + str(res) + '\n'

        except Exception as e:
            template = 'Error type: {0}.\nArguments: {1!r}.'
            err_message = template.format(type(e).__name__, e.args)
            except_times = except_times + 1
            if except_times < 2:
                continue
            else:
                return api, '\nFailed to call api. Result:\n' + err_message + '.\n'
        except:
            pass

def cloudflare_api(api, forward_address, cname_addess):
    res = ''
    if api.get('endpoint', '') == '':
        api['endpoint'] = 'https://api.cloudflare.com/client/v4'
    headers = {
        'X-Auth-Email': api['X-Auth-Email'],
        'X-Auth-Key': api['X-Auth-Key'],
        'Content-Type': 'application/json'
        }
    if api.get('zone_id', '') == '':
        res = requests.get(api['endpoint'] + '/zones', headers=headers, proxies=proxies)
        res = json.loads(res.content.decode('utf-8','ignore'))
        for zones in res['result']:
            if forward_address.split('@', 1)[1] == zones['name']:
                api['zone_id'] = zones['id']

    res = requests.get(api['endpoint'] + '/zones/' + api['zone_id'] + '/dns_records?per_page=100', headers=headers, proxies=proxies)
    res = json.loads(res.content.decode('utf-8','ignore'))
    for dns_record in res['result']:
        if (dns_record['name'] == forward_address.replace('@', '.')) & (dns_record['type'] == 'CNAME'):
            api['dns_record_id'] = dns_record['id']
            api['dns_record_content'] = dns_record['content']
            api['dns_record_ttl'] = dns_record['ttl']
    if cname_addess == api['dns_record_content']:
        return False, True, res, api
    else:
        data = {
            'type': 'CNAME',
            'name': forward_address.replace('@', '.'),
            'content': cname_addess,
            'ttl': api['dns_record_ttl'],
            'proxy': False
            }
        data = json.dumps(data)
        res = requests.put(api['endpoint'] + '/zones/' + api['zone_id'] + '/dns_records/' + api['dns_record_id'], data=data, headers=headers, proxies=proxies)
        
        res = json.loads(res.content.decode('utf-8','ignore'))
        return True, res['success'], res, api

if __name__ == '__main__':
    try:
        while(1):
            time.sleep(1)
            target, proxies = get_configuration()
            # THREADING
            trd = []
            for target_num in range(len(target)):
                trd.append(threading.Thread(target=start, args=(target_num, target[target_num], proxies,)))
                trd[-1].setDaemon(True)
                trd[-1].start()
                time.sleep(0.5)
            for thread in trd:
                thread.join()
            break

    except Exception as e:
        template = 'Crucial error type: {0}.\nArguments:\n{1!r}'
        err_message = template.format(type(e).__name__, e.args)
        print(err_message)
    except:
        pass
