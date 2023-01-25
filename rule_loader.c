#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define printable_ip(addr)           \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

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

    /*uint16_t source_port_mask;
    uint16_t dest_port_mask;
    uint8_t protocol_mask;*/

    int verdict;
    struct ipv4Rule *next;
};

struct ipv4Rule *ruleList;
// char *ruleFileName = "C:\\Users\\Jack\\Documents\\Year 4 Project\\opencl_firewalll\\rules.txt";
char *ruleFileName = "rules.txt";

int parseIntoIPv4(char *ipStr, uint32_t *binIP)
{
    int bufferInt[4];
    unsigned char bufferChr[4];
    sscanf(ipStr, "%[^.]%[^.]%[^.]%[^.]", bufferInt[3], bufferInt[2], bufferInt[1], bufferInt[0]);
    bufferChr[0] = (unsigned int)bufferInt[0];
    bufferChr[1] = (unsigned int)bufferInt[1];
    bufferChr[2] = (unsigned int)bufferInt[2];
    bufferChr[3] = (unsigned int)bufferInt[3];
    memcpy(binIP, bufferChr, 4);
    return 0;
}

struct ipv4Rule *parseRule(char *ruleString)
{
    char sourceIP[16], sourceMask[16], destIP[16], destMask[16];
    int sPort, dPort, protocol, verdict;
    struct ipv4Rule *rule;
    rule = malloc(sizeof(struct ipv4Rule));
    sscanf(ruleString, "%s %s %s %s %d %d %d %d", sourceIP, sourceMask, destIP, destMask, &sPort, &dPort, &protocol, &verdict);
    parseIntoIPv4(sourceIP, &(rule->source_ip));
    parseIntoIPv4(sourceMask, &(rule->source_ip_mask));
    parseIntoIPv4(destIP, &(rule->dest_ip));
    parseIntoIPv4(destMask, &(rule->dest_ip_mask));
    rule->source_port = (unsigned int)sPort;
    rule->dest_port = (unsigned int)dPort;
    rule->ip_protocol = (unsigned int)protocol;
    printf("just used parseRule\n");
    return rule;
}

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
                printf("point a is running\n");
            }
            else
            {
                ruleList->next = parseRule(rule);
                printf("point b is running\n");
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

int main()
{
    load_rules(ruleFileName);
    printf("IP ADDR %u.%u.%u.%u\n", ((unsigned char *)&(ruleList->source_ip))[3], ((unsigned char *)&(ruleList->source_ip))[2], ((unsigned char *)&(ruleList->source_ip))[1], ((unsigned char *)&(ruleList->source_ip))[0]);
    return 0;
}