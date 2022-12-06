#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>
#include <stdbool.h>
#include "src/src.h"
#include <linux/netfilter.h>

#include "variables.h"
#include "compare.h"

uint32_t rule_ip[rule_array_size];
uint32_t mask[rule_array_size];
int rule_verdict[rule_array_size];
int result[ip_array_size];

int compare_with_mask(uint32_t array_ip_input[], uint32_t rule_ip[], uint32_t mask[], int verdict[], int result[], int ip_arr_size, int rule_arr_size)
{
    // opencl structures
    cl_device_id deviceId;
    cl_context context;
    cl_program program;
    cl_kernel kernel_compare, kernel_sync;
    cl_command_queue queue;
    cl_int err;
    bool first_result[ip_arr_size * rule_arr_size];
    int rule_size[] = {rule_arr_size};
    // Data and Buffer
    cl_mem packet_buffer, rule_buffer, mask_buffer, verdict_buffer, output_buffer, result_buffer, rule_size_buffer;

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
    packet_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ip_arr_size * sizeof(uint32_t), array_ip_input, &err);
    print_err(err);

    rule_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint32_t), rule_ip, &err);
    print_err(err);

    mask_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint32_t), mask, &err);
    print_err(err);

    verdict_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(int), verdict, &err);
    print_err(err);

    rule_size_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(int), rule_size, &err);
    print_err(err);

    output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, rule_arr_size * ip_arr_size * sizeof(bool), first_result, &err);
    print_err(err);

    result_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ip_arr_size * sizeof(int), result, &err);
    print_err(err);

    queue = clCreateCommandQueueWithProperties(context, deviceId, 0, &err);
    print_err(err);

    // crate kernel_compare from source and func_compare
    kernel_compare = clCreateKernel(program, func_compare, &err);
    print_err(err);

    // set kernel_compare function arguments
    err = clSetKernelArg(kernel_compare, 0, sizeof(cl_mem), &packet_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 1, sizeof(cl_mem), &rule_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 2, sizeof(cl_mem), &mask_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel_compare, 3, sizeof(cl_mem), &output_buffer);
    print_err(err);

    // Enqueue kernel_compare to device
    err = clEnqueueNDRangeKernel(queue, kernel_compare, 2, global_offset, global_size, local_size, 0, NULL, NULL);
    print_err(err);

    // read result buffer in kernel_compare
    err = clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, ip_arr_size * rule_arr_size * sizeof(bool), first_result, 0, NULL, NULL);
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
