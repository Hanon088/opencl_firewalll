# opencl_firewalll

GPU Firewall based on Linux and OpenCL

prepare libnetfilter_queue
sudo ufw disable
sudo iptables -I INPUT -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -I INPUT -p icmp -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-num 0

To undo prep
sudo iptables -D INPUT -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -D INPUT -p icmp -j NFQUEUE --queue-num 0
sudo iptables -D OUTPUT -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -D OUTPUT -p icmp -j NFQUEUE --queue-num 0

To prep for multiple queues
sudo iptables -I INPUT -p tcp -m tcp --dport 80 -j NFQUEUE --queue-balance 0:5
sudo iptables -I INPUT -p icmp -j NFQUEUE --queue-balance 0:5
sudo iptables -I OUTPUT -p tcp -m tcp --dport 80 -j NFQUEUE --queue-balance 0:5
sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-balance 0:5
