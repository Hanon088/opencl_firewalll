#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>

#ifndef OPENCL_FIREWALLL_SRC_H
#define OPENCL_FIREWALLL_SRC_H

void print_err(cl_int err);
cl_device_id create_device_cl();
cl_program create_program_cl(cl_context clContext, cl_device_id deviceId, const char *filename);

int declare_rule_buffer_with_assign(
    cl_context *context,
    uint64_t rule_ip[],
    uint64_t rule_mask[],
    uint16_t rule_sport[],
    uint16_t rule_dport[],
    uint8_t rule_protocol[],
    int verdict[],
    int rule_arr_size);

int declare_input_buffer(
    cl_context *context,
    int ip_arr_size);

int declare_buffer(
    cl_context *context,
    uint64_t rule_ip[],
    uint64_t rule_mask[],
    uint16_t rule_sport[],
    uint16_t rule_dport[],
    uint8_t rule_protocol[],
    int verdict[],
    int result[],
    int rule_arr_size,
    int ip_arr_size);

int release_rule_buffer(
    cl_program *program,
    cl_context *context);

int release_input_buffer();

int release_buffer(
    cl_program *program,
    cl_context *context);

int compare(uint64_t input_ip[],
            uint16_t input_sport[],
            uint16_t input_dport[],
            uint8_t input_protocol[],
            cl_device_id *deviceId,
            cl_context *context,
            cl_program *program,
            int result[],
            int ip_arr_size,
            int rule_arr_size);

#endif // OPENCL_FIREWALLL_SRC_H