#include <linux/types.h>

#define ip_array_size 5
#define rule_array_size 4
extern const char *source;
extern const char *func_compare;
extern const char *func_sync;

extern uint32_t rule_ip[rule_array_size];
extern uint32_t mask[rule_array_size];
extern int rule_verdict[rule_array_size];
extern int result[ip_array_size];