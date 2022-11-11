//
// Created by Tanate on 11/11/2022.
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>
#include <stdbool.h>
#include "src/src.h"

const char *source = "C:\\Users\\User\\opencl_firewalll\\compare.cl";
const char *func = "compare";

// example value
#define printable_ip(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

// main_program


int main()
{
    // opencl structures
    cl_device_id deviceId;
    cl_context  context;
    cl_program  program;
    cl_kernel kernel;
    cl_command_queue queue;
    cl_int err;
    size_t local_size, global_size;

    //Data and Buffer
    cl_mem packet_buffer, rule_buffer, output_buffer;
    cl_int number_groups;
    uint32_t binary_ip; // input ip
    unsigned char string_ip[4];
    string_ip[3] = (unsigned int) 192;
    string_ip[2] = (unsigned int) 168;
    string_ip[1] = (unsigned int) 0;
    string_ip[0] = (unsigned int) 100;
    memcpy(&binary_ip, string_ip, 4);
    uint32_t arr_ip[10];// input ip array (uint32)
    uint32_t rule[1];// input rule (ip uint32)
    uint32_t mask[1];// input mask (mask uint32) (working)
    bool result[10];// output array order

    //initialize data copy ip and set rule(uint32_t array)
    for (int i=0; i<10; i++){
        arr_ip[i] = binary_ip;
    }
    // for example define all item == 192.168.0.100
    string_ip[3] = (unsigned int) 0;
    string_ip[2] = (unsigned int) 0;
    string_ip[1] = (unsigned int) 0;
    string_ip[0] = (unsigned int) 0;
    memcpy(&rule[0], string_ip, 4); // define rule == 0.0.0.0
    memcpy(&arr_ip[4], string_ip, 4); // define item number 4 to 0.0.0.0

    //check rule ip on cpu
    bool test;
    for(int i = 0 ; i < 10 ; i ++){
        test = arr_ip[i] == rule[0];
        printf("%d : %d\n",i,test);
    }
    printf("%s : %u.%u.%u.%u\n", "rule" ,printable_ip(rule[0]));

    //opencl path (GPU acc)

    //create cl_device
    deviceId = create_device_cl();
    //crate context
    context = clCreateContext(NULL, 1, &deviceId, NULL, NULL, &err);
    print_err(err);

    //build program;
    program = create_program_cl(context, deviceId, source);

    //define 10 workgroup 1 local workgroup
    global_size = 10;
    local_size = 1;
    number_groups = global_size/local_size;

    //create data_buffer for read and write
    packet_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 10* sizeof(uint32_t), arr_ip, &err);
    print_err(err);

    rule_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 1* sizeof(uint32_t), rule, &err);
    print_err(err);

    output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, number_groups * sizeof(bool),  result, &err);
    print_err(err);

    queue = clCreateCommandQueueWithProperties(context, deviceId, 0, &err);
    print_err(err);

    //crate kernel from source and func
    kernel = clCreateKernel(program, func ,&err);
    print_err(err);

    //set kernel function arguments
    err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &packet_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &rule_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel, 2 ,sizeof(cl_mem), &output_buffer);
    print_err(err);

    //Enqueue kernel to device
    err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    print_err(err);

    //read result buffer in kernel
    err = clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, sizeof(result), result, 0, NULL, NULL);
    print_err(err);

    //print result
    for(int i = 0; i<number_groups ; i++){
        printf("%d : %d\n", i ,result[i]);
    }

    //release resources
    clReleaseKernel(kernel);
    clReleaseMemObject(packet_buffer);
    clReleaseMemObject(rule_buffer);
    clReleaseMemObject(output_buffer);
    clReleaseCommandQueue(queue);
    clReleaseProgram(program);
    clRetainContext(context);
    return 0;
}