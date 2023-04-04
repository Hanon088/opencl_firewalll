#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>
#include "src/src.h"

#include "variables.h"
#include "rule_loader.h"

int compare(uint64_t input_ip[],
            uint16_t input_sport[],
            uint16_t input_dport[],
            uint8_t input_protocol[],
            cl_device_id *deviceId,
            cl_context *context,
            cl_program *program,
            int result[],
            int ip_arr_size,
            int rule_arr_size)
{
    // opencl structures
    cl_kernel kernel_compare, kernel_sync;
    cl_command_queue queue;
    cl_int err;

    // define 10 workgroup 1 local workgroup
    size_t global_size[] = {rule_arr_size, ip_arr_size};
    size_t local_size[] = {1, 1};
    size_t global_offset[] = {0, 0};

    queue = clCreateCommandQueueWithProperties(*context, *deviceId, 0, &err);
    print_err(err);

    err = clEnqueueWriteBuffer(queue, input_ip_buffer, CL_TRUE, 0, ip_arr_size * sizeof(uint64_t), input_ip, 0, NULL, NULL);
    print_err(err);

    err = clEnqueueWriteBuffer(queue, input_sport_buffer, CL_TRUE, 0, ip_arr_size * sizeof(uint16_t), input_sport, 0, NULL, NULL);
    print_err(err);

    err = clEnqueueWriteBuffer(queue, input_dport_buffer, CL_TRUE, 0, ip_arr_size * sizeof(uint16_t), input_dport, 0, NULL, NULL);
    print_err(err);

    err = clEnqueueWriteBuffer(queue, input_protocol_buffer, CL_TRUE, 0, ip_arr_size * sizeof(uint8_t), input_protocol, 0, NULL, NULL);
    print_err(err);

    // crate kernel_compare from source and func_compare
    kernel_compare = clCreateKernel(*program, func_compare, &err);
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

    kernel_sync = clCreateKernel(*program, func_sync, &err);
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
    clReleaseCommandQueue(queue);
    return 0;
}