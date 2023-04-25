import random

s_ip = [f"127.0.{i}.{j}" for i in range(240) for j in range(250)]
s_mask = ["255.255.0.0" for _ in range(240*250)]
d_ip = ["0.0.0.0" for _ in range(240*250)]
d_mask = ["0.0.0.0" for _ in range(240*250)]
proto = [["1", "6", "17"][i % 3] for i in range(240*250)]
s_port = ["0" for _ in range(240*250)]
d_port = list(random.sample(range(0, 2**16), 240*250))
verdict = [["0", "1"][i % 2] for i in range(240*250)]

rules = [
    f"{s_ip[i]} {s_mask[i]} {d_ip[i]} {d_mask[i]} {proto[i]} {s_port[i]} {d_port[i]} {verdict[i]} ;\n" for i in range(240*250)]

rules[-1] = "0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 0 0 0 1 ;"
rules = "".join(rules)

with open('rules_60k.txt', 'w') as f:
    print(rules, file=f)
