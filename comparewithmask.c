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

int compare_with_mask(uint32_t array_ip_input[] , uint32_t rule_ip[], uint32_t mask[], bool result[], int ip_array_size, int rule_array_size){
    // opencl structures
    cl_device_id deviceId;
    cl_context  context;
    cl_program  program;
    cl_kernel kernel;
    cl_command_queue queue;
    cl_int err;

    //Data and Buffer
    cl_mem packet_buffer, rule_buffer, mask_buffer, output_buffer;

    //create cl_device
    deviceId = create_device_cl();
    //crate context
    context = clCreateContext(NULL, 1, &deviceId, NULL, NULL, &err);
    print_err(err);

    //build program;
    program = create_program_cl(context, deviceId, source);

    //define 10 workgroup 1 local workgroup
    size_t global_size[] = {rule_array_size, ip_array_size};
    size_t local_size[] = {1, 1};
    size_t global_offset[] = {0,0};

    //create data_buffer for read and write
    packet_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ip_array_size* sizeof(uint32_t), array_ip_input, &err);
    print_err(err);

    rule_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_array_size* sizeof(uint32_t), rule_ip, &err);
    print_err(err);

    mask_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_array_size* sizeof(uint32_t), mask, &err);
    print_err(err);

    output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, rule_array_size*ip_array_size * sizeof(bool),  result, &err);
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
    err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &mask_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel, 3 ,sizeof(cl_mem), &output_buffer);
    print_err(err);

    //Enqueue kernel to device
    err = clEnqueueNDRangeKernel(queue, kernel, 2, global_offset, global_size, local_size, 0, NULL, NULL);
    print_err(err);

    //read result buffer in kernel
    err = clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, ip_array_size * rule_array_size * sizeof(bool), result, 0, NULL, NULL);
    print_err(err);
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



int main()
{
    int ip_array_size = 20;
    int rule_array_size = 4;
    uint32_t binary_ip; // input ip
    unsigned char string_ip[4];
    string_ip[3] = (unsigned int) 192;
    string_ip[2] = (unsigned int) 168;
    string_ip[1] = (unsigned int) 0;
    string_ip[0] = (unsigned int) 100;
    memcpy(&binary_ip, string_ip, 4);
    uint32_t array_ip_input[ip_array_size];// input ip array (uint32)
    uint32_t rule_ip[rule_array_size];// input rule_ip (ip uint32)
    uint32_t mask[rule_array_size];// input mask (mask uint32)
    bool result[ip_array_size*rule_array_size];// output array order

    //initialize data copy ip and set rule_ip(uint32_t array)
    for (int i=0; i<rule_array_size ; i++){
        string_ip[3] = (unsigned int) 192;
        string_ip[2] = (unsigned int) 168 + i;
        string_ip[1] = (unsigned int) 0;
        string_ip[0] = (unsigned int) 0;
        memcpy(&rule_ip[i], string_ip, 4);
        string_ip[3] = (unsigned int) 255;
        string_ip[2] = (unsigned int) 255;
        string_ip[1] = (unsigned int) 0;
        string_ip[0] = (unsigned int) 0;
        memcpy(&mask[i], string_ip, 4);
    }

    for (int i=0; i<ip_array_size; i++) {
        string_ip[3] = (unsigned int) 192;
        string_ip[2] = (unsigned int) 168;
        string_ip[1] = (unsigned int) 0;
        string_ip[0] = (unsigned int) 1 + i;
        memcpy(&binary_ip, string_ip, 4);
        array_ip_input[i] = binary_ip;
    }

    string_ip[3] = (unsigned int) 192;
    string_ip[2] = (unsigned int) 169;
    string_ip[1] = (unsigned int) 0;
    string_ip[0] = (unsigned int) 0;
    memcpy(&array_ip_input[4], string_ip, 4); // define item number 4 to 192.169.0.1

    string_ip[3] = (unsigned int) 192;
    string_ip[2] = (unsigned int) 169;
    string_ip[1] = (unsigned int) 0;
    string_ip[0] = (unsigned int) 1;
    memcpy(&array_ip_input[9], string_ip, 4);

    //check rule_ip ip on cpu
    bool test;
    for(int i = 0 ; i < rule_array_size ; i ++){
        printf("%s %d: %u.%u.%u.%u mask : %u.%u.%u.%u\n", "rule_ip", i , printable_ip(rule_ip[i]), printable_ip(mask[i]));;
    }
    for(int i = 0 ; i < ip_array_size ; i ++){
        for(int j = 0; j < rule_array_size ; j++){
            test = rule_ip[j] == (array_ip_input[i] & mask[j]);
            printf("%d",test);
            printf(" | %u.%u.%u.%u ", printable_ip(array_ip_input[i]));
        }
        printf("\n");
    }

    compare_with_mask(array_ip_input, rule_ip, mask, result, ip_array_size, rule_array_size);
    for(int i = 0; i< sizeof(result) / sizeof(bool) ; i++){
        printf("%d" ,result[i]);
        if(i%rule_array_size == rule_array_size-1){
            printf("\n");
        }
    }
}