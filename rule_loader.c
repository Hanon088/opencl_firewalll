#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "compare.h"
#include "variables.h"
#include "rule_loader.h"

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
    ruleAddr->verdict = verdict;
    ruleAddr->next = NULL;
    return 0;
}

int load_rules(const char *filename, struct ipv4Rule *ruleList)
{
    FILE *ruleFile;
    char *buffer;
    size_t ruleSize;
    char temp, rule[100];
    int countBuff = 0, countRule = 0, ruleNum = 0;
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
            ruleNum++;
            continue;
        }
        rule[countRule++] = temp;
    }
    free(buffer);
    return ruleNum;
}

int freeRules(struct ipv4Rule *ruleList)
{
    struct ipv4Rule *temp = ruleList;

    while (!temp)
    {
        ruleList = ruleList->next;
        free(temp);
        temp = ruleList;
    }
    return 0;
}

int ruleListToArr(struct ipv4Rule *ruleList, uint32_t *sAddr, uint32_t *sMask, uint32_t *dAddr, uint32_t *dMask, int *verdictArr)
{
    struct ipv4Rule *temp = ruleList;
    int count = 0;
    while (1)
    {

        memcpy(&sAddr[count], &temp->source_ip, 4);
        memcpy(&dAddr[count], &temp->dest_ip, 4);
        memcpy(&sMask[count], &temp->source_ip_mask, 4);
        memcpy(&dMask[count], &temp->dest_ip_mask, 4);
        memcpy(&verdictArr[count], &temp->verdict, sizeof(int));
        if (!(temp->next))
        {
            break;
        }
        count++;
        temp = temp->next;
    }
    return 0;
}
