#include <linux/types.h>
#define printable_ip(addr)           \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

int compare_with_mask(uint32_t array_ip_input[], uint32_t rule_ip[], uint32_t mask[], int verdict[], int result[], int ip_arr_size, int rule_arr_size);