# opencl_firewalll

GPU Firewall based on Linux and OpenCL

prepare libnetfilter_queue
sudo ufw disable
sudo iptables -I INPUT -p icmp -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-num 0

prepare half test
sudo iptables -I INPUT -p tcp --dport 443 -j NFQUEUE --queue-balance 0:2
sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-balance 0:2
sudo iptables -I INPUT -p icmp -j NFQUEUE --queue-balance 0:2
sudo iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-balance 0:2
sudo iptables -I OUTPUT -p icmp -j NFQUEUE --queue-balance 0:2

prepare full test
sudo iptables -I INPUT -p ALL -j NFQUEUE --queue-balance 0:1
sudo iptables -I OUTPUT -p ALL -j NFQUEUE --queue-balance 0:1

possible ways of connecting to OpenCL
-[] one single queue callback writes directly into device memory, starts device kernel then wait for device
-[] multiple queue callbacks write directly into device memory, start device kernel then wait for device

-[] single queue write to buffer, verdict thread waits for buffer to be full then sends buffer to OpenCL
-[] multiple queue write to buffer, verdict thread waits for buffer to be full then sends buffer to device

-[] multiple queue callbacks write directly into device memory, verdict thread waits for memory to be full then starts device kernel
