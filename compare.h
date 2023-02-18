#include <stdint.h>
#include "variables.h"

#define printable_ip(addr)           \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

extern uint64_t *rule_ip;
extern uint64_t *mask;
extern int *rule_verdict;
extern int result[ip_array_size];

int compare_with_mask(uint64_t array_ip_input[], uint64_t rule_ip[], uint64_t mask[], int verdict[], int result[], int ip_arr_size, int rule_arr_size);