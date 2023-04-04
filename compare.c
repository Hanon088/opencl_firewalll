#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>
#include <stdbool.h>
#include "src/src.h"
#include <linux/netfilter.h>

#include "variables.h"
#include "compare.h"

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