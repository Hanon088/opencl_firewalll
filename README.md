# opencl_firewalll
GPU Firewall based on Linux and OpenCL

prepare libnetfilter_queue
sudo ufw disable
sudo iptables -I INPUT -p icmp -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-num 0
