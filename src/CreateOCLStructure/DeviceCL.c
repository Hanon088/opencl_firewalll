//
// Created by User on 11/11/2022.
//
#include <stdio.h>
#include <string.h>
#include <CL/cl.h>
#include "src/src.h"

cl_device_id create_device_cl(){
    // find device CPU or GPU device are found and return
    char str_info[1024];
    cl_device_id device;
    cl_uint num_device;
    cl_int err;
    cl_platform_id platformId;
    err = clGetPlatformIDs(1, &platformId, NULL);
    print_err(err);
    err = clGetDeviceIDs(platformId, CL_DEVICE_TYPE_GPU, 1, &device, &num_device);
    if (err == CL_DEVICE_NOT_FOUND) {
        err = clGetDeviceIDs(platformId, CL_DEVICE_TYPE_CPU, 1, &device, &num_device);
        print_err(err);
    }
    err = clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(str_info), &str_info, NULL);
    print_err(err);
    printf("Found CL_DEVICE_NAME: %s\n", str_info);
    return device;
}

cl_program create_program_cl(cl_context clContext, cl_device_id deviceId, const char* filename){
    //read file and create cl_program
    cl_int err;
    print_err(err);
    cl_program program;
    FILE *program_handle;
    char *program_buffer, *program_log;
    size_t program_size, log_size;

    program_handle = fopen(filename, "r");
    if(program_handle == NULL){
        perror("Kernel File not found");
        exit(1);
    }
    fseek(program_handle, 0, SEEK_END);
    program_size = ftell(program_handle);
    rewind(program_handle);
    program_buffer = (char*) malloc(program_size + 1);
    program_buffer[program_size] = "\0";
    fread(program_buffer, sizeof (char), program_size, program_handle);
    fclose(program_handle);

    // create program from file
    program = clCreateProgramWithSource(clContext, 1, (const char**)&program_buffer, &program_size, &err);
    print_err(err);
    free(program_buffer);

    //build program
    err = clBuildProgram(program , 0, NULL, NULL, NULL, NULL);
    if(err < 0){
        char log[10240] = "";
        err = clGetProgramBuildInfo(program, deviceId, CL_PROGRAM_BUILD_LOG, sizeof(log), log, NULL);
        printf("Program build log:\n%s\n", log);
        exit(1);
    }
    print_err(err);
    return program;
}