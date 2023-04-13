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

int compare_old(uint64_t input_ip[],
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

    deviceId = create_device_cl();
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
    print_err(err);
    ;
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
    uint64_t input_ip[ip_array_size];                                // input ip array sd_ip(uint64)
    uint16_t input_sport[ip_array_size], input_dport[ip_array_size]; // input source_port destination_port
    uint8_t input_protocol[ip_array_size];                           // input protocol

    // rule input
    int result[ip_array_size]; // output array order

    uint64_t *rule_ip;
    uint64_t *rule_mask;
    uint8_t *rule_protocol;
    uint16_t *rule_s_port;
    uint16_t *rule_d_port;
    int *rule_verdict;
    int ruleNum;
    struct ipv4Rule *ruleList;

    ruleList = malloc(sizeof(struct ipv4Rule));
    ruleNum = load_rules(rule_file, ruleList);

    rule_ip = malloc(ruleNum * 8);
    rule_mask = malloc(ruleNum * 8);
    rule_protocol = malloc(ruleNum);
    rule_s_port = malloc(ruleNum * 2);
    rule_d_port = malloc(ruleNum * 2);
    rule_verdict = malloc(ruleNum * sizeof(int));

    printf("Number of rules %d\n", ruleNum);
    rule_list_to_arr_joined(ruleList, rule_ip, rule_mask, rule_protocol, rule_s_port, rule_d_port, rule_verdict);
    free_rule_list(ruleList);

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
        string_ip[0] = (unsigned int)1 + i;
        memcpy(&binary_ip, string_ip, 4);
        input_ip[i] = binary_ip;
        input_sport[i] = 0;
        input_dport[i] = 0;
        input_protocol[i] = 0;
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

    for (int i = 0; i < ruleNum; i++)
    {
        printf("RULE %d s %u.%u.%u.%u d %u.%u.%u.%u sm %u.%u.%u.%u dm %u.%u.%u.%u proto %d sp %u dp %u\n", i, printable_ip_joined(rule_ip[i]), printable_ip_joined(rule_mask[i]), rule_protocol[i], rule_s_port[i], rule_d_port[i]);
    }
    int int_verdict_buffer = 0;
    for (int i = 0; i < ip_array_size * ruleNum; i++)
    {

        if (rule_protocol[i % ruleNum] == 0)
        {
            protocol_input[i / ruleNum] = 0;
        }
        if (rule_s_port[i % ruleNum] == 0)
        {
            s_port_input[i / ruleNum] = 0;
        }
        if (rule_d_port[i % ruleNum] == 0)
        {
            d_port_input[i / ruleNum] = 0;
        }
        test = rule_ip[i % ruleNum] == (array_ip_input[i / ruleNum] & rule_mask[i % ruleNum]);
        protocol_result = (rule_protocol[i % ruleNum] == protocol_input[i / ruleNum]);
        sport_result = (rule_s_port[i % ruleNum] == s_port_input[i / ruleNum]);
        dport_result = (rule_d_port[i % ruleNum] == d_port_input[i / ruleNum]);
        //        printf("%d|", i / ruleNum);
        //        printf("%u.%u.%u.%u\n", printable_ip(array_ip_input[i/ruleNum]));
        if (test == 1)
        {
            verdict_buffer = rule_verdict[i % ruleNum];
            i += ruleNum - i % ruleNum;
            printf("%d", verdict_buffer);
            verdict_buffer = 0;
        }
        if (i % ruleNum == ruleNum - 1)
        {
            printf("%d", verdict_buffer);
            verdict_buffer = 0;
        }
    }
    printf("\n");
    for (int j = 0; j < 10; j++)
    {
        compare_old(input_ip, input_sport, input_dport, input_protocol, rule_ip, rule_mask, rule_s_port, rule_d_port, rule_protocol, rule_verdict, result, ip_array_size, ruleNum);
        for (int i = 0; i < sizeof(result) / sizeof(int); i++)
        {
            printf("%d", result[i]);
        }
        printf(" | %d\n", j);
    }
    freeRules(ruleList);
}