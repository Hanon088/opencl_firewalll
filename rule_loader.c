#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "compare.h"
#include "variables.h"
#include "rule_loader.h"

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

// struct ipv4Rule *ruleList = NULL;
//  char *ruleFileName = "C:\\Users\\Jack\\Documents\\Year 4 Project\\opencl_firewalll\\rules.txt";
//   char *ruleFileName = "rules.txt";

int parseIntoIPv4(char *ipStr, uint32_t *binIP)
{
    int bufferInt[4];
    unsigned char bufferChr[4];
    for (int i = 0; i < strlen(ipStr); i++)
    {
        if (ipStr[i] == '.')
        {
            ipStr[i] = ' ';
        }
    }
    sscanf(ipStr, "%d %d %d %d", &bufferInt[3], &bufferInt[2], &bufferInt[1], &bufferInt[0]);
    bufferChr[0] = (unsigned int)bufferInt[0];
    bufferChr[1] = (unsigned int)bufferInt[1];
    bufferChr[2] = (unsigned int)bufferInt[2];
    bufferChr[3] = (unsigned int)bufferInt[3];
    memcpy(binIP, bufferChr, 4);
    return 0;
}

int parseRule(char *ruleString, struct ipv4Rule *ruleAddr)
{
    char sourceIP[16], sourceMask[16], destIP[16], destMask[16];
    int sPort, dPort, protocol, verdict;
    sscanf(ruleString, "%s %s %s %s %d %d %d %d", sourceIP, sourceMask, destIP, destMask, &sPort, &dPort, &protocol, &verdict);
    parseIntoIPv4(sourceIP, &(ruleAddr->source_ip));
    parseIntoIPv4(sourceMask, &(ruleAddr->source_ip_mask));
    parseIntoIPv4(destIP, &(ruleAddr->dest_ip));
    parseIntoIPv4(destMask, &(ruleAddr->dest_ip_mask));
    ruleAddr->source_port = (unsigned int)sPort;
    ruleAddr->dest_port = (unsigned int)dPort;
    ruleAddr->ip_protocol = (unsigned int)protocol;
    return 0;
}

int load_rules(char *filename, struct ipv4Rule *ruleList)
{
    FILE *ruleFile;
    char *buffer;
    size_t ruleSize;
    char temp, rule[100];
    int countBuff = 0, countRule = 0;
    ruleFile = fopen(filename, "r");
    struct ipv4Rule *tempRule;
    int headLoaded = 0;
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

    while (countBuff < ruleSize)
    {
        temp = buffer[countBuff++];
        if (temp == ';')
        {
            if (!headLoaded)
            {
                // ruleList = malloc(sizeof(struct ipv4Rule));
                parseRule(rule, ruleList);
                headLoaded = 1;
            }
            else
            {
                tempRule = malloc(sizeof(struct ipv4Rule));
                parseRule(rule, tempRule);
                ruleList->next = tempRule;
            }
            memset(buffer, 0, sizeof(buffer));
            countRule = 0;
            continue;
        }
        rule[countRule++] = temp;
    }
    free(buffer);
    return 0;
}

int freeRules(struct ipv4Rule *ruleList)
{
}
/*int main()
{
    load_rules(ruleFileName);
    struct ipv4Rule *tempRule = ruleList;
    printf("IP ADDR %u.%u.%u.%u, MASK %u.%u.%u.%u\n", printable_ip(tempRule->source_ip), printable_ip(tempRule->source_ip_mask));
    tempRule = tempRule->next;
    printf("IP ADDR %u.%u.%u.%u, MASK %u.%u.%u.%u\n", printable_ip(tempRule->source_ip), printable_ip(tempRule->source_ip_mask));
    // free not implemented yet
    return 0;
}*/