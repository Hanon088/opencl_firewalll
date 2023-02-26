#include <stdint.h>
#include "variables.h"

#define printable_ip(addr)           \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

extern uint64_t *rule_ip;
extern uint64_t *rule_mask;
extern uint8_t *rule_protocol;
extern uint16_t *rule_s_port;
extern uint16_t *rule_d_port;
extern int *rule_verdict;
extern int result[ip_array_size];

int compare(uint64_t input_ip[],
            uint16_t input_sport[],
            uint16_t input_dport[],
            uint8_t input_protocol[],
            uint64_t rule_ip[],
            uint64_t rule_mask[],
            uint16_t rule_sport[],
            uint16_t rule_dport[],
            uint8_t rule_protocol[],
            int verdict[],
            int result[],
            int ip_arr_size,
            int rule_arr_size);