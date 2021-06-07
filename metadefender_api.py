import sys
import os
import codecs
import json
import requests
import urllib.parse
from termcolor import colored
from pathlib import Path


def script_path():
    '''set current path, to script path'''
    current_path = os.path.realpath(os.path.dirname(sys.argv[0]))
    os.chdir(current_path)
    return current_path
    
    
def read_file(filename, mode='r'):
    '''read from file'''
    content = ''
    try:
        with codecs.open(filename, mode, encoding='utf-8') as f:
            content = f.read()
            
    except Exception as err:
        print('failed to read from file: {}, err: {}'.format(filename, err))
        
    return content
    
    
def write_file(filename, text, mode='w'):
    '''write to file'''
    try:
        with codecs.open(filename, mode, encoding='utf-8') as f:
            f.write(text)
            
    except Exception as err:
        print('failed to write to file: {}, err: {}'.format(filename, err))
        
    return None
    
    
def write_json(filename, data):
    '''write to json file'''
    with open(filename, 'w') as fp:
        # ensure_ascii -> False/True -> characters/u'type'
        json.dump(data, fp, sort_keys=True, indent=4, ensure_ascii=False)
    return True
    
    
def read_json(filename):
    '''read json file to dict'''
    data = {}
    try:
        with open(filename) as f:
            data = json.load(f)
    except FileNotFoundError:
        print('[x] file not found: {}'.format(filename))
    return data
    
    
def metadefender_request(file_hash):
    '''metadefender request'''
    base_url = "https://api.metadefender.com/v4/hash/"
    url = urllib.parse.urljoin(base_url, file_hash)
    headers = {'apikey': "your_api_key"}
    response = requests.request("GET", url, headers=headers)
    response_json = response.json()
    
    if 'error' in response_json:
        key_hash = file_hash
        error_status = True
        return response_json, key_hash, error_status
        
    avs_data = {
        "name": response_json["file_info"].get('display_name', ''),
        "md5": response_json["file_info"].get('md5', '').lower(),
        "sha1": response_json["file_info"].get('sha1', '').lower(),
        "sha256": response_json["file_info"].get('sha256', '').lower(),
        "upload_timestamp": response_json["file_info"].get('upload_timestamp', ''),
        "size": int(response_json["file_info"].get('file_size', 0)),
        "progress_percentage": response_json["scan_results"].get('progress_percentage', ''),
        "scan_all_result_a": response_json["scan_results"].get('scan_all_result_a', ''),
        "engines": response_json["scan_results"]['total_avs'],
        "positives": response_json["scan_results"]['total_detected_avs'],
        "threat_name": response_json.get("threat_name", ''),
        "malware_family": response_json.get("malware_family", ''),
        "votes_up": response_json.get("votes", {}).get("up", 0),
        "votes_down": response_json.get("votes", {}).get("down", 0),
        }
        
    key_hash = avs_data.get('sha256', file_hash)
    error_status = False
    return avs_data, key_hash, error_status
    
    
if __name__ == "__main__":
    script_path()
    
    
    # ******* hashes files *******
    hashes_files_directory = Path('hashes_files')
    hashes_files = [hashes_files_directory.joinpath(item) for item in os.listdir(hashes_files_directory) if item.endswith('.txt')]
    hashes_list = []
    for filename in hashes_files:
        single = [line.strip() for line in read_file(filename).splitlines() if line.strip()]
        hashes_list.extend(single)
    hashes_list = sorted(list(set(hashes_list)))
    total_hashes = len(hashes_list)
    
    
    # ******* read db and collect known hashes *******
    metadefender_base_file = 'metadefender_base.json'
    metadefender_base = read_json(metadefender_base_file)
    metadefender_base_keys = list(metadefender_base.keys())
    metadefender_base_md5 = [value.get('md5', '') for value in metadefender_base.values() if value.get('md5', '')]
    metadefender_base_sha1 = [value.get('sha1', '') for value in metadefender_base.values() if value.get('sha1', '')]
    metadefender_base_sha256 = [value.get('sha256', '') for value in metadefender_base.values() if value.get('sha256', '')]
    metadefender_base_existing_hashes = tuple(set(metadefender_base_keys + metadefender_base_md5 + metadefender_base_sha1 + metadefender_base_sha256))
    
    
    store_error_response = True
    print('[*] store_error_response: {}\n'.format(store_error_response))
    
    for index, file_hash in enumerate(hashes_list):
        file_hash = file_hash.lower()
        try:
            print('{}/{}) {}'.format(index+1, total_hashes, file_hash))
            exists_in_base = (file_hash in metadefender_base_existing_hashes)
            
            if exists_in_base:
                print(colored('    [*] already exists in db', 'cyan'))
                print()
                continue
                
                
            # ******* request for data *******
            avs_data, key_hash, error_status = metadefender_request(file_hash)
            
            
            # ******* found info *******
            found_color = 'red'
            found_status = not error_status
            if found_status:
                found_color = 'green'
            print(colored('    [+] found: {}'.format(found_status), found_color))
            
            
            if error_status:
                # ******* show errors info *******
                """
                # example of errors:
                {"error": {"code": 404003,"messages": ["The hash was not found"]}}
                
                {'error': {'code': 400064, 'messages': ['The hash value is not valid']}}
                """
                if store_error_response:
                    metadefender_base[key_hash] = avs_data      # errors data
                code = avs_data["error"].get('code', '')
                code_str = '{}code: {}'.format(' '*8, code)
                messages = avs_data["error"].get('messages', [])
                messages_str = '{}messages: {}'.format(' '*8, messages)
                print(colored('    [x] request error:\n{}\n{}'.format(code_str, messages_str), 'yellow'))
                
            else:
                # ******* show results and update base *******
                metadefender_base[key_hash] = avs_data
                positives = avs_data['positives']
                engines = avs_data['engines']
                if not positives:
                    positives_color = 'green'
                elif 1 <= positives <= 5:
                    positives_color = 'yellow'
                else:
                    positives_color = 'red'
                print(colored('    [*] hits: {}/{}'.format(positives, engines), positives_color))
            print()
            
            
        except KeyboardInterrupt:
            print(colored('    [x] broken by user\n', 'cyan'))
            break
            
        except Exception as err:
            print('    [x] error catched: {}'.format(err))
            break
            
            
    write_json(metadefender_base_file, metadefender_base)
