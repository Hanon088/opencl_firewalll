#include "variables.h"
#include <linux/types.h>

const char *source = "/home/tanate/github/opencl_firewalll/compare.cl";
const char *func_compare = "compare";
const char *func_sync = "sync_rule_and_verdict";

unsigned char string_ip[4];
uint32_t rule_ip[rule_array_size];
uint32_t mask[rule_array_size];
int rule_verdict[rule_array_size];
int result[ip_array_size];