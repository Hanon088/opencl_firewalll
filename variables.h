#define ip_array_size 20
#define rule_array_size 10
#include <CL/cl.h>
extern const char *source;
extern const char *func_compare;
extern const char *func_sync;

extern const char *ruleFileName;

extern cl_mem rule_ip_buffer,
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
