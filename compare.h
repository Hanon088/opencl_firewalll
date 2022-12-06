#include <stdint.h>
#define printable_ip(addr)           \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

extern uint64_t rule_ip[rule_array_size];
extern uint64_t mask[rule_array_size];
extern int rule_verdict[rule_array_size];
extern int result[ip_array_size];

int compare_with_mask(uint64_t array_ip_input[], uint64_t rule_ip[], uint64_t mask[], int verdict[], int result[], int ip_arr_size, int rule_arr_size);