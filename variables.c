#include "variables.h"
#include <stdint.h>
#include <CL/cl.h>

const char *source = "/home/tanate/opencl_firewalll/compare.cl";
const char *func_compare = "compare";
const char *func_sync = "sync_rule_and_verdict";

const char *rule_file = "rules2.txt";

// opencl buffers
cl_mem rule_ip_buffer,
    rule_mask_buffer,
    rule_sport_buffer,
    rule_dport_buffer,
    rule_protocol_buffer,
    verdict_buffer,
    input_ip_buffer,
    input_sport_buffer,
    input_dport_buffer,
    input_protocol_buffer,
    output_buffer,
    result_buffer,
    rule_size_buffer;