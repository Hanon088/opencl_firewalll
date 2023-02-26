#include <stdint.h>

struct ipv4Rule
{
    /*
    assumes transport layer uses tcp/udp for now
    icmp types and others not taken into consideration
    */

    // source ip + dest ip = 64 bits
    uint32_t source_ip;
    uint32_t dest_ip;

    // source port + dest port + protocol = 40 bits
    uint16_t source_port;
    uint16_t dest_port;
    uint8_t ip_protocol;

    // masks to convert the packets
    uint32_t source_ip_mask;
    uint32_t dest_ip_mask;
    /*
    uint16_t source_port_mask;
    uint16_t dest_port_mask;
    uint8_t ip_protocol_mask;
    */

    int verdict;
    struct ipv4Rule *next;
};

int load_rules(const char *filename, struct ipv4Rule *ruleList);
int free_rule_list(struct ipv4Rule *ruleList);
int rule_list_to_arr(struct ipv4Rule *ruleList, uint32_t *sAddr, uint32_t *sMask, uint32_t *dAddr, uint32_t *dMask, uint8_t *protoArr, uint16_t *sPortArr, uint16_t *dPortArr, int *verdictArr);