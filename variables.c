#include "variables.h"
#include <stdint.h>

static int queue_num = 5;
static int queue_multipler = 2;
const char *source = "/home/tanate/opencl_firewalll/compare.cl";
const char *func_compare = "compare";
const char *func_sync = "sync_rule_and_verdict";

const char *rule_file = "rules.txt";