cmake_minimum_required(VERSION 3.23)
project(opencl_firewalll C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

#add when create new lib add only .c flie with dir

add_executable(compare comparewithmask.c src/PrintErr.c src/CreateOCLStructure/DeviceCL.c)

find_package(OpenCL REQUIRED)

target_link_libraries(compare OpenCL::OpenCL)