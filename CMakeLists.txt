cmake_minimum_required(VERSION 3.23)
project(opencl_firewalll C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

# add when create new lib add only .c flie with dir
add_executable(opencl_firewall opencl_firewall.c variables.c rule_loader.c src/PrintErr.c src/CreateOCLStructure/DeviceCL.c src/CreateOCLStructure/Buffer.c src/CreateOCLStructure/Compare.c)

find_package(OpenCL REQUIRED)

target_link_libraries(opencl_firewall OpenCL::OpenCL -lnetfilter_queue -lpthread)