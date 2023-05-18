"""
Generate rule for iptables which will match all on last
NOT TESTED YET
"""

import random

s_ip = [f"10.168.{i}.{j}" for i in range(40) for j in range(250)]
#s_mask = ["255.255.0.0" for _ in range(256*256)]
d_ip = ["0.0.0.0" for _ in range(40*250)]
#d_mask = ["0.0.0.0" for _ in range(256*256)]
#proto = [["1", "6", "17"][i % 3] for i in range(256*256)]
#s_port = ["0" for _ in range(256*256)]
#d_port = list(random.sample(range(0, 2**16), 256*256))
#verdict = [["0", "1"][i % 2] for i in range(256*256)]

rules = [
    f"iptables --insert FORWARD {i+1} --protocol all --src {s_ip[i]} --dst {d_ip[i]} --jump DROP\n" for i in range(40*250)]

rules[-1] = "iptables --append FORWARD --protocol all --jump ACCEPT"
rules = "".join(rules)

with open('iptables_rules_10k_new', 'w') as f:
    print(rules, file=f)
