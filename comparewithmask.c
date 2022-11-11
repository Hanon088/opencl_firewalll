//
// Created by Tanate on 11/11/2022.
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>
#include <stdbool.h>

// example value
#define printable_ip(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

// output opencl error
const char *getErrorString(cl_int error)
{
    switch(error){
        // run-time and JIT compiler errors
        case 0: return "CL_SUCCESS";
        case -1: return "CL_DEVICE_NOT_FOUND";
        case -2: return "CL_DEVICE_NOT_AVAILABLE";
        case -3: return "CL_COMPILER_NOT_AVAILABLE";
        case -4: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
        case -5: return "CL_OUT_OF_RESOURCES";
        case -6: return "CL_OUT_OF_HOST_MEMORY";
        case -7: return "CL_PROFILING_INFO_NOT_AVAILABLE";
        case -8: return "CL_MEM_COPY_OVERLAP";
        case -9: return "CL_IMAGE_FORMAT_MISMATCH";
        case -10: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
        case -11: return "CL_BUILD_PROGRAM_FAILURE";
        case -12: return "CL_MAP_FAILURE";
        case -13: return "CL_MISALIGNED_SUB_BUFFER_OFFSET";
        case -14: return "CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
        case -15: return "CL_COMPILE_PROGRAM_FAILURE";
        case -16: return "CL_LINKER_NOT_AVAILABLE";
        case -17: return "CL_LINK_PROGRAM_FAILURE";
        case -18: return "CL_DEVICE_PARTITION_FAILED";
        case -19: return "CL_KERNEL_ARG_INFO_NOT_AVAILABLE";

            // compile-time errors
        case -30: return "CL_INVALID_VALUE";
        case -31: return "CL_INVALID_DEVICE_TYPE";
        case -32: return "CL_INVALID_PLATFORM";
        case -33: return "CL_INVALID_DEVICE";
        case -34: return "CL_INVALID_CONTEXT";
        case -35: return "CL_INVALID_QUEUE_PROPERTIES";
        case -36: return "CL_INVALID_COMMAND_QUEUE";
        case -37: return "CL_INVALID_HOST_PTR";
        case -38: return "CL_INVALID_MEM_OBJECT";
        case -39: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
        case -40: return "CL_INVALID_IMAGE_SIZE";
        case -41: return "CL_INVALID_SAMPLER";
        case -42: return "CL_INVALID_BINARY";
        case -43: return "CL_INVALID_BUILD_OPTIONS";
        case -44: return "CL_INVALID_PROGRAM";
        case -45: return "CL_INVALID_PROGRAM_EXECUTABLE";
        case -46: return "CL_INVALID_KERNEL_NAME";
        case -47: return "CL_INVALID_KERNEL_DEFINITION";
        case -48: return "CL_INVALID_KERNEL";
        case -49: return "CL_INVALID_ARG_INDEX";
        case -50: return "CL_INVALID_ARG_VALUE";
        case -51: return "CL_INVALID_ARG_SIZE";
        case -52: return "CL_INVALID_KERNEL_ARGS";
        case -53: return "CL_INVALID_WORK_DIMENSION";
        case -54: return "CL_INVALID_WORK_GROUP_SIZE";
        case -55: return "CL_INVALID_WORK_ITEM_SIZE";
        case -56: return "CL_INVALID_GLOBAL_OFFSET";
        case -57: return "CL_INVALID_EVENT_WAIT_LIST";
        case -58: return "CL_INVALID_EVENT";
        case -59: return "CL_INVALID_OPERATION";
        case -60: return "CL_INVALID_GL_OBJECT";
        case -61: return "CL_INVALID_BUFFER_SIZE";
        case -62: return "CL_INVALID_MIP_LEVEL";
        case -63: return "CL_INVALID_GLOBAL_WORK_SIZE";
        case -64: return "CL_INVALID_PROPERTY";
        case -65: return "CL_INVALID_IMAGE_DESCRIPTOR";
        case -66: return "CL_INVALID_COMPILER_OPTIONS";
        case -67: return "CL_INVALID_LINKER_OPTIONS";
        case -68: return "CL_INVALID_DEVICE_PARTITION_COUNT";

            // extension errors
        case -1000: return "CL_INVALID_GL_SHAREGROUP_REFERENCE_KHR";
        case -1001: return "CL_PLATFORM_NOT_FOUND_KHR";
        case -1002: return "CL_INVALID_D3D10_DEVICE_KHR";
        case -1003: return "CL_INVALID_D3D10_RESOURCE_KHR";
        case -1004: return "CL_D3D10_RESOURCE_ALREADY_ACQUIRED_KHR";
        case -1005: return "CL_D3D10_RESOURCE_NOT_ACQUIRED_KHR";
        default: return "Unknown OpenCL error";
    }
}


//global var
char str_info[1024];
const char *source = "C:\\Users\\User\\opencl_firewalll\\compare.cl"; // CL kernel function file path
const char *func = "compare"; // CL Kernel function

void print_err(cl_int err){
    //check opencl error
    if(err < 0){
        printf("Log : %s\n", getErrorString(err));
        exit(1);
    }
}

cl_device_id device_cl(){
    // find device CPU or GPU device are found and return
    cl_device_id device;
    cl_uint num_device;
    cl_int err;
    cl_platform_id platformId;
    err = clGetPlatformIDs(1, &platformId, NULL);
    err = clGetDeviceIDs(platformId, CL_DEVICE_TYPE_GPU, 1, &device, &num_device);
    if (err == CL_DEVICE_NOT_FOUND) {
        err = clGetDeviceIDs(platformId, CL_DEVICE_TYPE_CPU, 1, &device, &num_device);
    }
    err = clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(str_info), &str_info, NULL);
    print_err(err);
    printf("Found CL_DEVICE_NAME: %s\n", str_info);
    return device;
}

cl_program create_program(cl_context clContext, cl_device_id deviceId, const char* filename){
    //read file and create cl_program
    cl_program program;
    FILE *program_handle;
    char *program_buffer, *program_log;
    size_t program_size, log_size;
    int err;

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

int main()
{
    // opencl structures
    cl_device_id deviceId;
    cl_context  context;
    cl_program  program;
    cl_kernel kernel;
    cl_command_queue queue;
    cl_int err;
    size_t local_size, global_size;

    //Data and Buffer
    cl_mem packet_buffer, rule_buffer, output_buffer;
    cl_int number_groups;
    uint32_t binary_ip; // input ip
    unsigned char string_ip[4];
    string_ip[3] = (unsigned int) 192;
    string_ip[2] = (unsigned int) 168;
    string_ip[1] = (unsigned int) 0;
    string_ip[0] = (unsigned int) 100;
    memcpy(&binary_ip, string_ip, 4);
    uint32_t arr_ip[10];// input ip array (uint32)
    uint32_t rule[1];// input rule (ip uint32)
    uint32_t mask[1];// input mask (mask uint32) (working)
    bool result[10];// output array order

    //initialize data copy ip and set rule(uint32_t array)
    for (int i=0; i<10; i++){
        arr_ip[i] = binary_ip;
    }
    // for example define all item == 192.168.0.100
    string_ip[3] = (unsigned int) 0;
    string_ip[2] = (unsigned int) 0;
    string_ip[1] = (unsigned int) 0;
    string_ip[0] = (unsigned int) 0;
    memcpy(&rule[0], string_ip, 4); // define rule == 0.0.0.0
    memcpy(&arr_ip[4], string_ip, 4); // define item number 4 to 0.0.0.0

    //check rule ip on cpu
    bool test;
    for(int i = 0 ; i < 10 ; i ++){
        test = arr_ip[i] == rule[0];
        printf("%d : %d\n",i,test);
    }
    printf("%s : %u.%u.%u.%u\n", "rule" ,printable_ip(rule[0]));

    //opencl path (GPU acc)

    //create cl_device
    deviceId = device_cl();
    //crate context
    context = clCreateContext(NULL, 1, &deviceId, NULL, NULL, &err);
    print_err(err);

    //build program;
    program = create_program(context , deviceId, source);

    //define 10 workgroup 1 local workgroup
    global_size = 10;
    local_size = 1;
    number_groups = global_size/local_size;

    //create data_buffer for read and write
    packet_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 10* sizeof(uint32_t), arr_ip, &err);
    print_err(err);

    rule_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 1* sizeof(uint32_t), rule, &err);
    print_err(err);

    output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, number_groups * sizeof(bool),  result, &err);
    print_err(err);

    queue = clCreateCommandQueueWithProperties(context, deviceId, 0, &err);
    print_err(err);

    //crate kernel from source and func
    kernel = clCreateKernel(program, func ,&err);
    print_err(err);

    //set kernel function arguments
    err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &packet_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &rule_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel, 2 ,sizeof(cl_mem), &output_buffer);
    print_err(err);

    //Enqueue kernel to device
    err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_size, &local_size, 0, NULL, NULL);
    print_err(err);

    //read result buffer in kernel
    err = clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, sizeof(result), result, 0, NULL, NULL);
    print_err(err);

    //print result
    for(int i = 0; i<number_groups ; i++){
        printf("%d : %d\n", i ,result[i]);
    }

    //release resources
    clReleaseKernel(kernel);
    clReleaseMemObject(packet_buffer);
    clReleaseMemObject(rule_buffer);
    clReleaseMemObject(output_buffer);
    clReleaseCommandQueue(queue);
    clReleaseProgram(program);
    clRetainContext(context);
    return 0;
}