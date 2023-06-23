# opencl_firewalll

GPU Firewall based on Linux and OpenCL

This is a project from students of the Faculty of Information Technology, King Monkut's Institute of Technology Ladkrabang.

### Important branches are

- [ ] main: Main program, not turned into service/daemon yet

- [ ] OpenCL-acc: Development of the OpenCL part of the program

Other branches are experiments we use to test the system

### To Compile and Run

(require sudo privilege)

cmake CMakeLists.txt

make

Prepare iptables nfqueue rules, example in tests/prep_env

./opencl_firewall
