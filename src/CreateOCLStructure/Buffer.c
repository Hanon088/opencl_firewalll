#include <string.h>
#include <CL/cl.h>
#include "src/src.h"

#include "variables.h"
#include "rule_loader.h"

int declare_rule_buffer_with_assign(
    cl_context *context,
    uint64_t rule_ip[],
    uint64_t rule_mask[],
    uint16_t rule_sport[],
    uint16_t rule_dport[],
    uint8_t rule_protocol[],
    int verdict[],
    int rule_arr_size

)
{
    cl_int err;
    rule_ip_buffer = clCreateBuffer(*context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint64_t), rule_ip, &err);
    print_err(err);

    rule_mask_buffer = clCreateBuffer(*context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint64_t), rule_mask, &err);
    print_err(err);

    rule_sport_buffer = clCreateBuffer(*context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint16_t), rule_sport, &err);
    print_err(err);

    rule_dport_buffer = clCreateBuffer(*context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint16_t), rule_dport, &err);
    print_err(err);

    rule_protocol_buffer = clCreateBuffer(*context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint8_t), rule_protocol, &err);
    print_err(err);

    verdict_buffer = clCreateBuffer(*context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(int), verdict, &err);
    print_err(err);
}

int declare_input_buffer(
    cl_context *context,
    int ip_arr_size)
{
    cl_int err;
    input_ip_buffer = clCreateBuffer(*context, CL_MEM_READ_WRITE, ip_arr_size * sizeof(uint64_t), NULL, &err);
    print_err(err);

    input_sport_buffer = clCreateBuffer(*context, CL_MEM_READ_WRITE, ip_arr_size * sizeof(uint16_t), NULL, &err);
    print_err(err);

    input_dport_buffer = clCreateBuffer(*context, CL_MEM_READ_WRITE, ip_arr_size * sizeof(uint16_t), NULL, &err);
    print_err(err);

    input_protocol_buffer = clCreateBuffer(*context, CL_MEM_READ_ONLY, ip_arr_size * sizeof(uint8_t), NULL, &err);
    print_err(err);
}

int declare_buffer(
    cl_context *context,
    uint64_t rule_ip[],
    uint64_t rule_mask[],
    uint16_t rule_sport[],
    uint16_t rule_dport[],
    uint8_t rule_protocol[],
    int verdict[],
    int rule_arr_size,
    int ip_arr_size)
{
    cl_int err;
    //    int first_result[ip_arr_size * rule_arr_size];
    int rule_size[] = {rule_arr_size};
    declare_rule_buffer_with_assign(context, rule_ip, rule_mask, rule_sport, rule_dport, rule_protocol, verdict, rule_arr_size);
    declare_input_buffer(context, ip_arr_size);
    rule_size_buffer = clCreateBuffer(*context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(int), rule_size, &err);
    print_err(err);

    output_buffer = clCreateBuffer(*context, CL_MEM_READ_WRITE, rule_arr_size * ip_arr_size * sizeof(int), NULL, &err);
    print_err(err);

    result_buffer = clCreateBuffer(*context, CL_MEM_READ_WRITE, ip_arr_size * sizeof(int), NULL, &err);
    print_err(err);
}

int release_rule_buffer(
    cl_program *program,
    cl_context *context)
{
    clReleaseMemObject(rule_ip_buffer);
    clReleaseMemObject(rule_mask_buffer);
    clReleaseMemObject(rule_sport_buffer);
    clReleaseMemObject(rule_dport_buffer);
    clReleaseMemObject(rule_protocol_buffer);
    clReleaseMemObject(verdict_buffer);
    clReleaseProgram(*program);
    clReleaseContext(*context);
}

int release_input_buffer()
{

    clReleaseMemObject(input_ip_buffer);
    clReleaseMemObject(input_sport_buffer);
    clReleaseMemObject(input_dport_buffer);
    clReleaseMemObject(input_protocol_buffer);
}

int release_buffer(
    cl_program *program,
    cl_context *context)
{
    release_rule_buffer(program, context);
    release_input_buffer();
    clReleaseMemObject(output_buffer);
    clReleaseMemObject(result_buffer);
    clReleaseMemObject(rule_size_buffer);
}