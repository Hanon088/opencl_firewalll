//
// Created by User on 3/29/2023.
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>
#include "src/src.h"

#include "variables.h"
#include "rule_loader.h"

#define printable_ip(addr)           \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]


int main(){
    uint32_t binary_ip; // input ip
    unsigned char string_ip[4];
    string_ip[3] = (unsigned int)192;
    string_ip[2] = (unsigned int)168;
    string_ip[1] = (unsigned int)0;
    string_ip[0] = (unsigned int)100;
    memcpy(&binary_ip, string_ip, 4);

    // packet input
    uint64_t input_ip[ip_array_size]; // input ip array sd_ip(uint64)
    uint16_t input_sport[ip_array_size], input_dport[ip_array_size]; // input source_port destination_port
    uint8_t input_protocol[ip_array_size]; // input protocol

    //rule input
    int verdict[rule_array_size];
    int result[ip_array_size]; // output array order
    uint64_t rule_ip[rule_array_size] , rule_mask[rule_array_size];
    uint32_t sAddr[rule_array_size], dAddr[rule_array_size], sMask[rule_array_size], dMask[rule_array_size], mergeBuff[2];
    uint16_t sPort[rule_array_size], dPort[rule_array_size];
    uint8_t protocols[rule_array_size];
    int tempVerdict[rule_array_size];
    int ruleNum;
    struct ipv4Rule *ruleList;

    ruleList = malloc(sizeof(struct ipv4Rule));
    ruleNum = load_rules(ruleFileName, ruleList);
    printf("Number of rules %d\n", ruleNum);
    ruleListToArr(ruleList, sAddr, sMask, dAddr, dMask, protocols, sPort, dPort, tempVerdict);


    /*for (int i = 0; i < ruleNum; i++)
    {
        printf("SOURCE : %u.%u.%u.%u Mask : %u.%u.%u.%u DEST : %u.%u.%u.%u Mask : %u.%u.%u.%u Verdict: %d\n", printable_ip(sAddr[i]), printable_ip(sMask[i]), printable_ip(dAddr[i]), printable_ip(dMask[i]), tempVerdict[i]);
    }*/

//    freeRules(ruleList);

    // initialize data copy ip and set rule_ip(uint64_t array)

    for (int i = 0; i < ip_array_size; i++)
    {
        string_ip[3] = (unsigned int)192;
        string_ip[2] = (unsigned int)168;
        string_ip[1] = (unsigned int)0;
        string_ip[0] = (unsigned int)1+i;
        memcpy(&binary_ip, string_ip, 4);
        input_ip[i] = binary_ip;
        input_sport[i] = 80;
        input_dport[i] = 0;
        input_protocol[i] = 0;
    }
    for (int i = 0; i < rule_array_size; i++)
    {
        mergeBuff[0] = sAddr[i];
        mergeBuff[1] = dAddr[i];
        memcpy(&rule_ip[i], mergeBuff, 8);
        mergeBuff[0] = sMask[i];
        mergeBuff[1] = dMask[i];
        memcpy(&rule_mask[i], mergeBuff, 8);
        verdict[i] = tempVerdict[i];
    }

    string_ip[3] = (unsigned int)192;
    string_ip[2] = (unsigned int)200;
    string_ip[1] = (unsigned int)0;
    string_ip[0] = (unsigned int)1;
    memcpy(&input_ip[4], string_ip, 4); // define item number 4 to 192.169.0.1

    string_ip[3] = (unsigned int)192;
    string_ip[2] = (unsigned int)171;
    string_ip[1] = (unsigned int)0;
    string_ip[0] = (unsigned int)1;
    memcpy(&input_ip[9], string_ip, 4);

    // check rule_ip ip on cpu
    // wearied output on cpu but in opencl work fine
    int test, protocol_result, sport_result, dport_result;
    for (int i = 0; i < rule_array_size; i++)
    {
        printf("%s %d: %u.%u.%u.%u rule_mask : %u.%u.%u.%u : sport: %u : dport: %u : protocol : %u : verdict : %d\n", "rule_ip", i, printable_ip(rule_ip[i]), printable_ip(rule_mask[i]), (unsigned int)sPort[i], (unsigned int)dPort[i] , (unsigned int)protocols[i],verdict[i]);
    }
    int int_verdict_buffer = 0;
    for (int i = 0; i < ip_array_size * rule_array_size; i++)
    {
        if(protocols[i % rule_array_size] == 0){input_protocol[i / rule_array_size] = 0;}
        if(sPort[i % rule_array_size] == 0){input_sport[i / rule_array_size] = 0;}
        if(dPort[i % rule_array_size] == 0){input_dport[i / rule_array_size] = 0;}
        test = rule_ip[i % rule_array_size] == (input_ip[i / rule_array_size] & rule_mask[i % rule_array_size]);
        protocol_result = (protocols[i % rule_array_size] == input_protocol[i / rule_array_size]);
        sport_result = (sPort[i % rule_array_size] == input_sport[i / rule_array_size]);
        dport_result = (dPort[i % rule_array_size] == input_dport[i / rule_array_size]);
        test = protocol_result & sport_result & dport_result & test;
//        printf("%d|", i / rule_array_size);
//        printf("%u.%u.%u.%u | %d | %u.%u.%u.%u | %d | %d |\n", printable_ip(input_ip[i/rule_array_size]), test, printable_ip(rule_ip[i % rule_array_size]), i % rule_array_size, i);
        if (test == 1)
        {
            int_verdict_buffer = verdict[i % rule_array_size];
            i += rule_array_size - i % rule_array_size;
            i--;
            printf("%d", int_verdict_buffer);
            verdict_buffer = 0;
        }
        else if (i % rule_array_size == (rule_array_size - 1))
        {
            printf("%d", int_verdict_buffer);
            verdict_buffer = 0;
        }

    }
    printf("\n");

    // build OpenCL Resources
    cl_device_id deviceId;
    cl_context context;
    cl_program program;
    cl_int err;
    // query devices
    deviceId = create_device_cl();
    // create context
    context = clCreateContext(NULL, 1, &deviceId, NULL, NULL, &err);
    print_err(err);

    // build program;
    program = create_program_cl(context, deviceId,source);

    // create all buffer Rule(with value) and input
    declare_buffer(&context, rule_ip, rule_mask, sPort, dPort, protocols, tempVerdict, result, rule_array_size, ip_array_size);

    for (int j = 0; j < 10; j++)
    {
        for (int i = 0; i < sizeof(result) / sizeof(int); i++)
        {
            compare(input_ip, input_sport, input_dport, input_protocol, &deviceId, &context, &program, result, ip_array_size, rule_array_size);
            printf("%d", result[i]);
        }
        printf(" | %d\n", j);
    }
    freeRules(ruleList);
    // release all resources
    release_buffer(&program, &context);
}