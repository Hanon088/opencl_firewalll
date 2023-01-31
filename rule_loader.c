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

struct ipv4Rule *ruleList = NULL;
char *ruleFileName = "C:\\Users\\Jack\\Documents\\Year 4 Project\\opencl_firewalll\\rules.txt";
// char *ruleFileName = "rules.txt";

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
    // printf("%d %d %d %d\n", bufferInt[3], bufferInt[2], bufferInt[1], bufferInt[0]);
    bufferChr[0] = (unsigned int)bufferInt[0];
    bufferChr[1] = (unsigned int)bufferInt[1];
    bufferChr[2] = (unsigned int)bufferInt[2];
    bufferChr[3] = (unsigned int)bufferInt[3];
    // printf("%u %u %u %u\n", bufferChr[3], bufferChr[2], bufferChr[1], bufferChr[0]);
    memcpy(binIP, bufferChr, 4);
    // printf("%u %u %u %u\n", ((unsigned char *)binIP)[3], ((unsigned char *)binIP)[2], ((unsigned char *)binIP)[1], ((unsigned char *)binIP)[0]);
    return 0;
}

int parseRule(char *ruleString, struct ipv4Rule *ruleAddr)
{
    char sourceIP[16], sourceMask[16], destIP[16], destMask[16];
    int sPort, dPort, protocol, verdict;
    /*struct ipv4Rule *rule;
    rule = malloc(sizeof(struct ipv4Rule));*/
    sscanf(ruleString, "%s %s %s %s %d %d %d %d", sourceIP, sourceMask, destIP, destMask, &sPort, &dPort, &protocol, &verdict);
    // printf("%s %s %s %s\n", sourceIP, sourceMask, destIP, destMask);
    parseIntoIPv4(sourceIP, &(ruleAddr->source_ip));
    parseIntoIPv4(sourceMask, &(ruleAddr->source_ip_mask));
    parseIntoIPv4(destIP, &(ruleAddr->dest_ip));
    parseIntoIPv4(destMask, &(ruleAddr->dest_ip_mask));
    ruleAddr->source_port = (unsigned int)sPort;
    ruleAddr->dest_port = (unsigned int)dPort;
    ruleAddr->ip_protocol = (unsigned int)protocol;
    return 0;
}

void load_rules(char *filename)
{
    FILE *ruleFile;
    char *buffer;
    size_t ruleSize;
    char temp, rule[100];
    int countBuff = 0, countRule = 0;
    ruleFile = fopen(filename, "r");
    struct ipv4Rule *tempRule;
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
    // printf("%s\nruleSize: %d\n", buffer, ruleSize);

    // change this loop into sscanf?
    while (countBuff < ruleSize)
    {
        temp = buffer[countBuff++];
        // printf("%c", temp);
        if (temp == ';')
        {
            if (ruleList == NULL)
            {
                ruleList = malloc(sizeof(struct ipv4Rule));
                parseRule(rule, ruleList);
                /*printf("point a is running\n");
                printf("IP ADDR %u.%u.%u.%u\n", printable_ip(ruleList->source_ip));
                printf("MASK %u.%u.%u.%u\n", printable_ip(ruleList->source_ip_mask));
                printf("UINT %u\n", ruleList->source_ip);
                printf("ADDR %p\n", ruleList);*/
            }
            else
            {
                tempRule = malloc(sizeof(struct ipv4Rule));
                parseRule(rule, tempRule);
                ruleList->next = tempRule;
                // printf("point b is running\n");
            }
            memset(buffer, 0, sizeof(buffer));
            countRule = 0;
            continue;
        }
        rule[countRule++] = temp;
        // printf("RULESIZE: %d, COUNTBUFF: %d, COUNTRULE: %d, TEMP: %c\n", ruleSize, countBuff, countRule, temp);
        //  printf("%s\n", rule);
    }
    free(buffer);
}

int main()
{
    load_rules(ruleFileName);
    struct ipv4Rule *tempRule = ruleList;
    printf("IP ADDR %u.%u.%u.%u, MASK %u.%u.%u.%u\n", printable_ip(tempRule->source_ip), printable_ip(tempRule->source_ip_mask));
    tempRule = tempRule->next;
    printf("IP ADDR %u.%u.%u.%u, MASK %u.%u.%u.%u\n", printable_ip(tempRule->source_ip), printable_ip(tempRule->source_ip_mask));
    return 0;
}