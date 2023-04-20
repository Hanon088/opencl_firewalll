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

int main()
{
    uint32_t binary_ip; // input ip
    unsigned char string_ip[4];
    string_ip[3] = (unsigned int)192;
    string_ip[2] = (unsigned int)168;
    string_ip[1] = (unsigned int)0;
    string_ip[0] = (unsigned int)100;
    memcpy(&binary_ip, string_ip, 4);

    // packet input
    uint64_t input_ip[ip_array_size];                                // input ip array sd_ip(uint64)
    uint16_t input_sport[ip_array_size], input_dport[ip_array_size]; // input source_port destination_port
    uint8_t input_protocol[ip_array_size];                           // input protocol

    int result[ip_array_size]; // output array order

    uint64_t *rule_ip;
    uint64_t *rule_mask;
    uint8_t *rule_protocol;
    uint16_t *rule_s_port;
    uint16_t *rule_d_port;
    int *rule_verdict;
    int ruleNum;
    struct ipv4Rule *ruleList;

    ruleList = malloc(sizeof(struct ipv4Rule));
    ruleNum = load_rules(rule_file, ruleList);

    rule_ip = malloc(ruleNum * 8);
    rule_mask = malloc(ruleNum * 8);
    rule_protocol = malloc(ruleNum);
    rule_s_port = malloc(ruleNum * 2);
    rule_d_port = malloc(ruleNum * 2);
    rule_verdict = malloc(ruleNum * sizeof(int));

    printf("Number of rules %d\n", ruleNum);
    rule_list_to_arr_joined(ruleList, rule_ip, rule_mask, rule_protocol, rule_s_port, rule_d_port, rule_verdict);
    free_rule_list(ruleList);

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
        string_ip[0] = (unsigned int)1 + i;
        memcpy(&binary_ip, string_ip, 4);
        input_ip[i] = binary_ip;
        input_sport[i] = 80;
        input_dport[i] = 0;
        input_protocol[i] = 0;
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
    for (int i = 0; i < ruleNum; i++)
    {
        printf("RULE %d s %u.%u.%u.%u d %u.%u.%u.%u sm %u.%u.%u.%u dm %u.%u.%u.%u proto %d sp %u dp %u\n", i, printable_ip_joined(rule_ip[i]), printable_ip_joined(rule_mask[i]), rule_protocol[i], rule_s_port[i], rule_d_port[i]);
    }
    int int_verdict_buffer = 0;
//    int int_verdict_buffer[ruleNum];
    for (int i = 0; i < ip_array_size * ruleNum; i++)
    {

        if (rule_protocol[i % ruleNum] == 0)
        {
            input_protocol[i / ruleNum] = 0;
        }
        if (rule_s_port[i % ruleNum] == 0)
        {
            input_sport[i / ruleNum] = 0;
        }
        if (rule_d_port[i % ruleNum] == 0)
        {
            input_dport[i / ruleNum] = 0;
        }
        test = rule_ip[i % ruleNum] == (input_ip[i / ruleNum] & rule_mask[i % ruleNum]);
        protocol_result = (rule_protocol[i % ruleNum] == input_protocol[i / ruleNum]);
        sport_result = (rule_s_port[i % ruleNum] == input_sport[i / ruleNum]);
        dport_result = (rule_d_port[i % ruleNum] == input_dport[i / ruleNum]);
        test = test & protocol_result & sport_result & dport_result;
        if (!test){
            test = 6;
        }
        else if (test == 1){
            test = rule_verdict[i % ruleNum];
        }
        int_verdict_buffer += test;
        if((int_verdict_buffer / 6 != ruleNum) & (i % ruleNum == ruleNum -1)){
            if(int_verdict_buffer % 6 != 0){
                printf("%d", int_verdict_buffer % 6);
            }else{
                printf("%d", int_verdict_buffer % 6);
            }
            int_verdict_buffer = 0;
        }else if(int_verdict_buffer / 6 == ruleNum){
            printf("%d", int_verdict_buffer % 6);
            int_verdict_buffer = 0;
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
    program = create_program_cl(context, deviceId, source);

    // create all buffer Rule(with value) and input
    declare_buffer(&context, rule_ip, rule_mask, rule_s_port, rule_d_port, rule_protocol, rule_verdict, result, ruleNum, ip_array_size);

    for (int j = 0; j < 10; j++)
    {
        for (int i = 0; i < sizeof(result) / sizeof(int); i++)
        {
            compare(input_ip, input_sport, input_dport, input_protocol, &deviceId, &context, &program, result, ip_array_size, ruleNum);
            printf("%d", result[i]);
        }
        printf(" | %d\n", j);
    }

    // release all resources
    free(rule_ip);
    free(rule_mask);
    free(rule_protocol);
    free(rule_s_port);
    free(rule_d_port);
    free(rule_verdict);
    release_buffer(&program, &context);
}