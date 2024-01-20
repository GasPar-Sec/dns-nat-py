import dns.query
import dns.zone
import dns.update
import argparse
import json
import re
import copy
from time import sleep

parser = argparse.ArgumentParser()
parser.add_argument('--nsSource', type=str, required=True)
parser.add_argument('--ipSrc', type=str, required=True)
parser.add_argument('--ipDst', type=str, required=True)
parser.add_argument('--nsFinal', type=str)
parser.add_argument('--alterPath',type=str)
args = parser.parse_args()

domain_sync=args.nsSource
ip_src=args.ipSrc
ip_dst=args.ipDst


domain_final=domain_sync if args.nsFinal is None else args.nsFinal

NAME=0
TTL=1
RDTYPE=3
VALUE=4
simple_rec_type=['A']

def get_alter(json_path):
    if json_path==None: return None
    try:
        with open(json_path,'r') as f:
            json_text = f.read()
            json_loaded=json.loads(json_text)
    except:
        return None
    
    return json_loaded
        
def alter(alter_value):
    global alter_action
    if alter_action==None : return alter_value

    final_value=copy.deepcopy(alter_value)

    try:
        for type_alter in alter_action['alter']:
            if type_alter['type']=='subnet':
                if check_subnet(final_value):
                    for action in type_alter['action']:
                        if action['action_type'] == 'replace':
                            final_value=replace_act(final_value,action['from'],action['by'])

    except KeyError as e:
        print(f'Error Missing "{e.args[0]}" in "alter_action" json')

    return final_value
    
def replace_act(value,from_c,to_c):
    return value.replace(from_c,to_c)
    
def check_subnet(to_check):
    pattern = re.compile("^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return bool(pattern.match(to_check))


if __name__ == '__main__':

    alter_action=get_alter(args.alterPath)
    update_dns = dns.update.Update(f'{domain_final}.')
    z = dns.zone.from_xfr(dns.query.xfr(ip_src, domain_sync))
    sleep(5) #Need to add sleep to get around a strange timeout error on the line above.
    names = z.nodes.keys()
    for n in names:
        list_dns_rec=z[n].to_text(n).split(' ')
        if list_dns_rec[RDTYPE] in simple_rec_type:
            update_dns.add(list_dns_rec[NAME], list_dns_rec[TTL], list_dns_rec[RDTYPE], alter(list_dns_rec[VALUE]))
            response=dns.query.tcp(update_dns, ip_dst)
        elif list_dns_rec[RDTYPE]=='SRV':
            update_dns.add(list_dns_rec[NAME],z[n].rdatasets[0])
            response=dns.query.tcp(update_dns, ip_dst)
