cmake_minimum_required(VERSION 3.16)
project(opencl_firewalll C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

# add when create new lib add only .c flie with dir
add_executable(compare comparewithmask.c src/PrintErr.c src/CreateOCLStructure/DeviceCL.c rule_loader.c variables.c)

add_executable(compare_refactored compare_main.c src/PrintErr.c src/CreateOCLStructure/DeviceCL.c rule_loader.c variables.c src/CreateOCLStructure/Buffer.c src/CreateOCLStructure/Compare.c)

find_package(OpenCL REQUIRED)

target_link_libraries(compare OpenCL::OpenCL)
target_link_libraries(compare_refactored OpenCL::OpenCL)