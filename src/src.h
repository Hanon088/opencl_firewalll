//
// Created by User on 11/11/2022.
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>

#ifndef OPENCL_FIREWALLL_SRC_H
#define OPENCL_FIREWALLL_SRC_H

void print_err(cl_int err);
cl_device_id create_device_cl();
cl_program create_program_cl(cl_context clContext, cl_device_id deviceId, const char* filename);

#endif //OPENCL_FIREWALLL_SRC_H
