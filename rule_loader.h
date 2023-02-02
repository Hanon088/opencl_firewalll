#include <stdint.h>

struct ipv4Rule;

int load_rules(char *filename, struct ipv4Rule *ruleList);
int freeRules(struct ipv4Rule *ruleList);