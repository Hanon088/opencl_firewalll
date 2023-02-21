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

#include "variables.h"
#include "rule_loader.h"

// example value
#define printable_ip(addr)           \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

// main_program

int compare(uint64_t input_ip[],
            uint16_t input_sport[],
            uint16_t input_dport[],
            uint8_t input_protocol[],
            uint64_t rule_ip[],
            uint64_t rule_mask[],
            uint16_t rule_sport[],
            uint16_t rule_dport[],
            uint8_t rule_protocol[],
            int verdict[],
            int result[],
            int ip_arr_size,
            int rule_arr_size)
{
    // opencl structures
    cl_device_id deviceId;
    cl_context context;
    cl_program program;
    cl_kernel kernel_compare, kernel_sync;
    cl_command_queue queue;
    cl_int err;
    int first_result[ip_arr_size * rule_arr_size];
    int rule_size[] = {rule_arr_size};
    // Data and Buffer
    cl_mem input_ip_buffer,
            input_sport_buffer,
            input_dport_buffer,
            input_protocol_buffer,
            rule_ip_buffer,
            rule_mask_buffer,
            rule_sport_buffer,
            rule_dport_buffer,
            rule_protocol_buffer,
            verdict_buffer,
            output_buffer,
            result_buffer,
            rule_size_buffer;

    // create cl_device
    deviceId = create_device_cl();

    long mem_size;
    err = clGetDeviceInfo(deviceId, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(long), &mem_size, NULL);
    printf("GLOBAL_MEM_SIZE : %ld MB \n", mem_size / 1000000);

    // crate context
    context = clCreateContext(NULL, 1, &deviceId, NULL, NULL, &err);
    print_err(err);

    // build program;
    program = create_program_cl(context, deviceId, source);

    // define 10 workgroup 1 local workgroup
    size_t global_size[] = {rule_arr_size, ip_arr_size};
    size_t local_size[] = {1, 1};
    size_t global_offset[] = {0, 0};

    // create data_buffer for read and write
    input_ip_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ip_arr_size * sizeof(uint64_t), input_ip, &err);
    print_err(err);

    input_sport_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ip_arr_size * sizeof(uint16_t), input_sport, &err);
    print_err(err);

    input_dport_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ip_arr_size * sizeof(uint16_t), input_dport, &err);
    print_err(err);

    input_protocol_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ip_arr_size * sizeof(uint8_t), input_protocol, &err);
    print_err(err);

    rule_ip_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint64_t), rule_ip, &err);
    print_err(err);

    rule_mask_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint64_t), rule_mask, &err);
    print_err(err);

    rule_sport_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint16_t), rule_sport, &err);
    print_err(err);

    rule_dport_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint16_t), rule_dport, &err);
    print_err(err);

    rule_protocol_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint8_t), rule_protocol, &err);
    print_err(err);

    verdict_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(int), verdict, &err);
    print_err(err);

    rule_size_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(int), rule_size, &err);
    print_err(err);

    output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, rule_arr_size * ip_arr_size * sizeof(int), first_result, &err);
    print_err(err);

    result_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ip_arr_size * sizeof(int), result, &err);
    print_err(err);

    queue = clCreateCommandQueueWithProperties(context, deviceId, 0, &err);
    print_err(err);

    // crate kernel_compare from source and func_compare
    kernel_compare = clCreateKernel(program, func_compare, &err);
    print_err(err);

    // set kernel_compare function arguments
    err = clSetKernelArg(kernel_compare, 0, sizeof(cl_mem), &input_ip_buffer);
    print_err(err);;
    err |= clSetKernelArg(kernel_compare, 1, sizeof(cl_mem), &input_sport_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 2, sizeof(cl_mem), &input_dport_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 3, sizeof(cl_mem), &input_protocol_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 4, sizeof(cl_mem), &rule_ip_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 5, sizeof(cl_mem), &rule_mask_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 6, sizeof(cl_mem), &rule_sport_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 7, sizeof(cl_mem), &rule_dport_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 8, sizeof(cl_mem), &rule_protocol_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 9, sizeof(cl_mem), &output_buffer);
    print_err(err);

    // Enqueue kernel_compare to device
    err = clEnqueueNDRangeKernel(queue, kernel_compare, 2, global_offset, global_size, local_size, 0, NULL, NULL);
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

    size_t sync_work_group[] = {ip_arr_size};
    size_t sync_local[] = {1};

    err = clEnqueueNDRangeKernel(queue, kernel_sync, 1, 0, sync_work_group, sync_local, 0, NULL, NULL);
    print_err(err);

    err = clEnqueueReadBuffer(queue, result_buffer, CL_TRUE, 0, ip_arr_size * sizeof(int), result, 0, NULL, NULL);
    print_err(err);

    // release resources
    clReleaseKernel(kernel_compare);
    clReleaseKernel(kernel_sync);
    clReleaseMemObject(input_ip_buffer);
    clReleaseMemObject(input_sport_buffer);
    clReleaseMemObject(input_dport_buffer);
    clReleaseMemObject(input_protocol_buffer);
    clReleaseMemObject(rule_ip_buffer);
    clReleaseMemObject(rule_mask_buffer);
    clReleaseMemObject(rule_sport_buffer);
    clReleaseMemObject(rule_dport_buffer);
    clReleaseMemObject(rule_protocol_buffer);
    clReleaseMemObject(verdict_buffer);
    clReleaseMemObject(output_buffer);
    clReleaseMemObject(result_buffer);
    clReleaseMemObject(rule_size_buffer);
    clReleaseCommandQueue(queue);
    clReleaseProgram(program);
    clReleaseContext(context);
    return 0;
}

int main()
{
    uint32_t binary_ip; // input ip
    unsigned char string_ip[4];
    string_ip[3] = (unsigned int)192;
    string_ip[2] = (unsigned int)168;
    string_ip[1] = (unsigned int)0;
    string_ip[0] = (unsigned int)100;
    memcpy(&binary_ip, string_ip, 4);

    // packet input
    uint64_t input_ip[ip_array_size]; // input ip array sd_ip(uint64)
    uint16_t input_sport[ip_array_size], input_dport[ip_array_size]; // input source_port destination_port
    uint8_t input_protocol[ip_array_size]; // input protocol

    //rule input
    int verdict[rule_array_size];
    int result[ip_array_size]; // output array order
    uint64_t rule_ip[rule_array_size] , rule_mask[rule_array_size];
    uint32_t sAddr[rule_array_size], dAddr[rule_array_size], sMask[rule_array_size], dMask[rule_array_size], mergeBuff[2];
    uint16_t sPort[rule_array_size], dPort[rule_array_size];
    uint8_t protocols[rule_array_size];
    int tempVerdict[rule_array_size];
    int ruleNum;
    struct ipv4Rule *ruleList;

    ruleList = malloc(sizeof(struct ipv4Rule));
    ruleNum = load_rules(ruleFileName, ruleList);
    printf("Number of rules %d\n", ruleNum);
    ruleListToArr(ruleList, sAddr, sMask, dAddr, dMask, protocols, sPort, dPort, tempVerdict);


    /*for (int i = 0; i < ruleNum; i++)
    {
        printf("SOURCE : %u.%u.%u.%u Mask : %u.%u.%u.%u DEST : %u.%u.%u.%u Mask : %u.%u.%u.%u Verdict: %d\n", printable_ip(sAddr[i]), printable_ip(sMask[i]), printable_ip(dAddr[i]), printable_ip(dMask[i]), tempVerdict[i]);
    }*/

//    freeRules(ruleList);

    // initialize data copy ip and set rule_ip(uint64_t array)

    for (int i = 0; i < ip_array_size; i++)
    {
        string_ip[3] = (unsigned int)192;
        string_ip[2] = (unsigned int)168;
        string_ip[1] = (unsigned int)0;
        string_ip[0] = (unsigned int)1+i;
        memcpy(&binary_ip, string_ip, 4);
        input_ip[i] = binary_ip;
        input_sport[i] = 0;
        input_dport[i] = 0;
        input_protocol[i] = 0;
    }
    for (int i = 0; i < rule_array_size; i++)
    {
        mergeBuff[0] = sAddr[i];
        mergeBuff[1] = dAddr[i];
        memcpy(&rule_ip[i], mergeBuff, 8);
        mergeBuff[0] = sMask[i];
        mergeBuff[1] = dMask[i];
        memcpy(&rule_mask[i], mergeBuff, 8);
        verdict[i] = tempVerdict[i];
    }

    string_ip[3] = (unsigned int)192;
    string_ip[2] = (unsigned int)200;
    string_ip[1] = (unsigned int)0;
    string_ip[0] = (unsigned int)1;
    memcpy(&input_ip[4], string_ip, 4); // define item number 4 to 192.169.0.1

    string_ip[3] = (unsigned int)192;
    string_ip[2] = (unsigned int)171;
    string_ip[1] = (unsigned int)0;
    string_ip[0] = (unsigned int)1;
    memcpy(&input_ip[9], string_ip, 4);

    // check rule_ip ip on cpu
    // wearied output on cpu but in opencl work fine
    int test, protocol_result, sport_result, dport_result;
    for (int i = 0; i < rule_array_size; i++)
    {
        printf("%s %d: %u.%u.%u.%u rule_mask : %u.%u.%u.%u : verdict : %d\n", "rule_ip", i, printable_ip(rule_ip[i]), printable_ip(rule_mask[i]), verdict[i]);
    }
    int verdict_buffer = 0;
    for (int i = 0; i < ip_array_size * rule_array_size; i++)
    {
        if(protocols[i % rule_array_size] == 0){input_protocol[i / rule_array_size] = 0;}
        if(sPort[i % rule_array_size] == 0){input_sport[i / rule_array_size] = 0;}
        if(dPort[i % rule_array_size] == 0){input_dport[i / rule_array_size] = 0;}
        test = rule_ip[i % rule_array_size] == (input_ip[i / rule_array_size] & rule_mask[i % rule_array_size]);
        protocol_result = (protocols[i % rule_array_size] == input_protocol[i / rule_array_size]);
        sport_result = (sPort[i % rule_array_size] == input_sport[i / rule_array_size]);
        dport_result = (dPort[i % rule_array_size] == input_dport[i / rule_array_size]);
//        printf("%d|", i / rule_array_size);
//        printf("%u.%u.%u.%u\n", printable_ip(input_ip[i/rule_array_size]));
        if (test == 1)
        {
            verdict_buffer = verdict[i % rule_array_size];
            i += rule_array_size - i % rule_array_size;
            printf("%d", verdict_buffer);
            verdict_buffer = 0;
        }
        if (i % rule_array_size == rule_array_size - 1)
        {
            printf("%d", verdict_buffer);
            verdict_buffer = 0;
        }
    }
    printf("\n");
    for (int j = 0; j < 1; j++)
    {
        compare(input_ip, input_sport, input_dport, input_protocol, rule_ip,rule_mask, sPort, dPort, protocols, tempVerdict, result, ip_array_size, rule_array_size);
        for (int i = 0; i < sizeof(result) / sizeof(int); i++)
        {
            printf("%d", result[i]);
        }
        printf("\n");
    }
    freeRules(ruleList);
}