//
// Created by Tanate on 11/11/2022.
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>
#include <stdbool.h>
#include <time.h>
#include "src/src.h"

const char *source = "C:\\Users\\User\\opencl_firewalll\\compare.cl";
const char *func_compare = "compare";
const char *func_sync = "sync_rule_and_verdict";

// example value
#define printable_ip(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

// main_program

int compare_with_mask(uint32_t array_ip_input[] , uint32_t rule_ip[], uint32_t mask[], int verdict[], int result[], int ip_array_size, int rule_array_size){
    // opencl structures
    cl_device_id deviceId;
    cl_context  context;
    cl_program  program;
    cl_kernel kernel_compare, kernel_sync;
    cl_command_queue queue;
    cl_int err;
    bool first_result[ip_array_size*rule_array_size];
    int rule_size[] = {rule_array_size};
    //Data and Buffer
    cl_mem packet_buffer, rule_buffer, mask_buffer, verdict_buffer, output_buffer, result_buffer, rule_size_buffer;

    //create cl_device
    deviceId = create_device_cl();

    long mem_size;
    err = clGetDeviceInfo(deviceId, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(long), &mem_size, NULL);
    printf("GLOBAL_MEM_SIZE : %ld MB \n", mem_size/1000000);

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

    verdict_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_array_size* sizeof(int), verdict, &err);
    print_err(err);

    rule_size_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(int), rule_size, &err);
    print_err(err);

    output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, rule_array_size*ip_array_size * sizeof(bool),  first_result, &err);
    print_err(err);

    result_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ip_array_size * sizeof(int),  result, &err);
    print_err(err);



    queue = clCreateCommandQueueWithProperties(context, deviceId, 0, &err);
    print_err(err);

    //crate kernel_compare from source and func_compare
    kernel_compare = clCreateKernel(program, func_compare , &err);
    print_err(err);

    //set kernel_compare function arguments
    err = clSetKernelArg(kernel_compare, 0, sizeof(cl_mem), &packet_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 1, sizeof(cl_mem), &rule_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 2, sizeof(cl_mem), &mask_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 3 , sizeof(cl_mem), &output_buffer);
    print_err(err);

    //Enqueue kernel_compare to device
    err = clEnqueueNDRangeKernel(queue, kernel_compare, 2, global_offset, global_size, local_size, 0, NULL, NULL);
    print_err(err);

    //read result buffer in kernel_compare
    err = clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, ip_array_size * rule_array_size * sizeof(bool), first_result, 0, NULL, NULL);
    print_err(err);

    kernel_sync = clCreateKernel(program, func_sync, &err);
    print_err(err);

    err = clSetKernelArg(kernel_sync, 0, sizeof(cl_mem), &output_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_sync, 1, sizeof(cl_mem), &verdict_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_sync, 2, sizeof(cl_mem), &result_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_sync, 3, sizeof(cl_mem), &rule_size_buffer);
    print_err(err);

    size_t sync_work_group[] = {ip_array_size};
    size_t sync_local[] = {1};

    err = clEnqueueNDRangeKernel(queue, kernel_sync, 1, 0, sync_work_group, sync_local, 0, NULL, NULL);
    print_err(err);

    err = clEnqueueReadBuffer(queue, result_buffer, CL_TRUE, 0, ip_array_size * sizeof(int), result, 0, NULL, NULL);
    print_err(err);

    //release resources
    clReleaseKernel(kernel_compare);
    clReleaseKernel(kernel_sync);
    clReleaseMemObject(packet_buffer);
    clReleaseMemObject(rule_buffer);
    clReleaseMemObject(verdict_buffer);
    clReleaseMemObject(output_buffer);
    clReleaseMemObject(result_buffer);
    clReleaseMemObject(rule_size_buffer);
    clReleaseMemObject(mask_buffer);
    clReleaseCommandQueue(queue);
    clReleaseProgram(program);
    clReleaseContext(context);
    return 0;
}



int main()
{
    int ip_array_size = 20;
    int rule_array_size = 5;
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
    int verdict[rule_array_size];
    int result[ip_array_size];// output array order

    //initialize data copy ip and set rule_ip(uint32_t array)
    verdict[0] = 1;
    verdict[1] = 0;
    verdict[2] = 4;
    verdict[3] = 5;
    srand(time(0));
    for (int i=0; i<rule_array_size ; i++){
        string_ip[3] = (unsigned int) 192;
        string_ip[2] = (unsigned int) 168+(rand()%10+1);
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
        string_ip[2] = (unsigned int) 168+i;
        string_ip[1] = (unsigned int) 0;
        string_ip[0] = (unsigned int) 1;
        memcpy(&binary_ip, string_ip, 4);
        array_ip_input[i] = binary_ip;
    }

    string_ip[3] = (unsigned int) 192;
    string_ip[2] = (unsigned int) 200;
    string_ip[1] = (unsigned int) 0;
    string_ip[0] = (unsigned int) 1;
    memcpy(&array_ip_input[4], string_ip, 4); // define item number 4 to 192.169.0.1

    string_ip[3] = (unsigned int) 192;
    string_ip[2] = (unsigned int) 171;
    string_ip[1] = (unsigned int) 0;
    string_ip[0] = (unsigned int) 1;
    memcpy(&array_ip_input[9], string_ip, 4);


    //check rule_ip ip on cpu
    bool test;
    for(int i = 0 ; i < rule_array_size ; i ++){
        printf("%s %d: %u.%u.%u.%u mask : %u.%u.%u.%u : verdict : %d\n", "rule_ip", i , printable_ip(rule_ip[i]), printable_ip(mask[i]), verdict[i]);
    }
    int verdict_buffer = 0;
    for(int i = 0 ; i < ip_array_size*rule_array_size ; i ++){
        test = rule_ip[i%rule_array_size] == (array_ip_input[i/rule_array_size] & mask[i%rule_array_size]);
     if(test){
            verdict_buffer = verdict[i%rule_array_size];
            i += rule_array_size - i%rule_array_size;
            printf("%d", verdict_buffer);
            verdict_buffer = 0;
        }
        if(i%rule_array_size == rule_array_size-1){
            printf("%d", verdict_buffer);
            verdict_buffer = 0;
        }
    }
    printf("\n");
    for(int j = 0 ; j<1000 ; j ++) {
        compare_with_mask(array_ip_input, rule_ip, mask, verdict, result, ip_array_size, rule_array_size);
        for (int i = 0; i < sizeof(result) / sizeof(int); i++) {
            printf("%d", result[i]);
        }
        printf("\n");
    }


}