# opencl_firewalll
GPU Firewall based on Linux and OpenCL

prepare libnetfilter_queue
sudo ufw disable
sudo iptables -I INPUT -p icmp -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-num 0

prepare half test
sudo iptables -I INPUT -p tcp --dport 443 -j NFQUEUE --queue-balance 0:1
sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-balance 0:1
sudo iptables -I INPUT -p icmp -j NFQUEUE --queue-balance 0:1
sudo iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-balance 0:1
sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-balance 0:1

prepare full test
sudo iptables -I INPUT -p ALL -j NFQUEUE --queue-balance 0:1
sudo iptables -I OUTPUT -p ALL -j NFQUEUE --queue-balance 0:1
