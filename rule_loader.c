#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct ipv4Rule
{
    // masks to convert the packets
    uint32_t source_ip_mask;
    uint32_t dest_ip_mask;
    uint16_t source_port_mask;
    uint16_t dest_port_mask;
    uint8_t protocol_mask;

    // source ip + dest ip = 64 bits
    uint32_t source_ip;
    uint32_t dest_ip;

    // source port + dest port + protocol = 36 bits
    uint16_t source_port;
    uint16_t dest_port;
    uint8_t protocol;

    int verdict;
    struct ipv4Rule *next;
};

struct ipv4Rule *ruleList;

void load_rules(char *filename)
{
    FILE *ruleFile;
    char *buffer;
    size_t ruleSize;
    char temp, rule[100];
    int countBuff = 0, countRule = 0;

    ruleFile = fopen(filename, "r");
    if (!ruleFile)
    {
        fprintf(stderr, "Rule File Not Found\n");
        exit(1);
    }
    fseek(ruleFile, 0, SEEK_END);
    ruleSize = ftell(ruleFile);
    rewind(ruleFile);
    buffer = (char *)malloc(ruleSize + 1);
    buffer[ruleSize] = '\0';
    fread(buffer, sizeof(char), ruleSize, ruleFile);
    fclose(ruleFile);

    while (temp = buffer[countBuff++] != '\0')
    {
        if (temp == '\n' || temp == '\r')
        {
            if (countRule == 0)
            {
                continue;
            }
            if (!ruleList)
            {
                ruleList = parseRule(rule);
            }
            else
            {
                ruleList->next = parseRule(rule);
            }
            for (int i = 0; i < countRule; i++)
            {
                rule[i] = '\0';
            }
            countRule = 0;
            continue;
        }
        rule[countRule++] = temp;
    }
    free(buffer);
}

struct ipv4Rule *parseRule(char *ruleString)
{
    char sourceIP[16], sourceMask[16], destIP[16], destMask[16];
    int sPort, dPort, protocol;
    struct ipv4Rule *rule;
    rule = malloc(sizeof(struct ipv4Rule));
    sscanf(ruleString, "%s %s %s %s %d %d %d", sourceIP, sourceMask, destIP, destMask, &sPort, &dPort, &protocol);
}