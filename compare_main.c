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

    // packet input
    uint64_t input_ip[ip_array_size];                                // input ip array sd_ip(uint64)
    uint16_t input_sport[ip_array_size], input_dport[ip_array_size]; // input source_port destination_port
    uint8_t input_protocol[ip_array_size];                           // input protocol

    // packet input
    uint64_t input_ip_gpu[ip_array_size];                                    // input ip array sd_ip(uint64)
    uint16_t input_sport_gpu[ip_array_size], input_dport_gpu[ip_array_size]; // input source_port destination_port
    uint8_t input_protocol_gpu[ip_array_size];                               // input protocol

    uint64_t maskSink[ip_array_size];
    int verdictSink[ip_array_size];

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

    // initialize data copy ip and set rule_ip(uint64_t array)

    ruleList = malloc(sizeof(struct ipv4Rule));
    // load_rules("C:\\Users\\User\\opencl_firewalll\\packets.txt", ruleList);
    load_rules("packets.txt", ruleList);
    rule_list_to_arr_joined(ruleList, input_ip, maskSink, input_protocol, input_sport, input_dport, verdictSink);
    rule_list_to_arr_joined(ruleList, input_ip_gpu, maskSink, input_protocol_gpu, input_sport_gpu, input_dport_gpu, verdictSink);
    free_rule_list(ruleList);

    // check rule_ip ip on cpu
    // wearied output on cpu but in opencl work fine
    int test,
        protocol_result, sport_result, dport_result;
    for (int i = 0; i < ruleNum; i++)
    {
        printf("RULE %d s %u.%u.%u.%u d %u.%u.%u.%u sm %u.%u.%u.%u dm %u.%u.%u.%u proto %d sp %u dp %u verdict %d\n", i, printable_ip_joined(rule_ip[i]), printable_ip_joined(rule_mask[i]), rule_protocol[i], rule_s_port[i], rule_d_port[i], rule_verdict[i]);
    }
    printf("\n--------------------------------------\n\n");
    printf("PACKETS CPU\n");
    for (int i = 0; i < ip_array_size; i++)
    {
        printf("PACKET %d s %u.%u.%u.%u d %u.%u.%u.%u proto %d sp %u dp %u\n", i, printable_ip_joined(input_ip[i]), input_protocol[i], input_sport[i], input_dport[i]);
    }
    printf("\nPACKETS GPU\n");
    for (int i = 0; i < ip_array_size; i++)
    {
        printf("PACKET %d s %u.%u.%u.%u d %u.%u.%u.%u proto %d sp %u dp %u\n", i, printable_ip_joined(input_ip_gpu[i]), input_protocol_gpu[i], input_sport_gpu[i], input_dport_gpu[i]);
    }
    printf("\n");

    int int_verdict_buffer = 0;
    for (int i = 0; i < ip_array_size * ruleNum; i++)
    {
        int protocol_buffer = input_protocol[i / ruleNum];
        int sport_buffer = input_sport[i / ruleNum];
        int dport_buffer = input_dport[i / ruleNum];

        if (rule_protocol[i % ruleNum] == 0)
        {
            protocol_buffer = 0;
        }
        if (rule_s_port[i % ruleNum] == 0)
        {
            sport_buffer = 0;
        }
        if (rule_d_port[i % ruleNum] == 0)
        {
            dport_buffer = 0;
        }
        test = rule_ip[i % ruleNum] == (input_ip[i / ruleNum] & rule_mask[i % ruleNum]);
        protocol_result = (rule_protocol[i % ruleNum] == protocol_buffer);
        sport_result = (rule_s_port[i % ruleNum] == sport_buffer);
        dport_result = (rule_d_port[i % ruleNum] == dport_buffer);
        printf("rule_proto: %d, input_proto: %d, ", rule_protocol[i % ruleNum], input_protocol[i / ruleNum]);
        printf("test: %d, protocol: %d, sport: %d, dport: %d", test, protocol_result, sport_result, dport_result);
        test = test & protocol_result & sport_result & dport_result;
        printf("|--%d++%d|", i % ruleNum, test);
        printf("%u.%u.%u.%u\n", printable_ip(input_ip[i / ruleNum]));
        if (test == 1)
        {
            int_verdict_buffer = rule_verdict[i % ruleNum];
            i += (ruleNum - i % ruleNum) - 1;
            printf("%d", int_verdict_buffer);
            int_verdict_buffer = 0;
        }
        else if (i % ruleNum == ruleNum - 1)
        {
            printf("%d", int_verdict_buffer);
            int_verdict_buffer = 0;
        }
        printf("\n");
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

    compare(input_ip_gpu, input_sport_gpu, input_dport_gpu, input_protocol_gpu, &deviceId, &context, &program, result, ip_array_size, ruleNum);
    for (int i = 0; i < sizeof(result) / sizeof(int); i++)
    {
        printf("%d", result[i]);
    }

    /*for (int j = 0; j < 10; j++)
    {
        for (int i = 0; i < sizeof(result) / sizeof(int); i++)
        {
            compare(input_ip_gpu, input_sport_gpu, input_dport_gpu, input_protocol_gpu, &deviceId, &context, &program, result, ip_array_size, ruleNum);
            printf("%d", result[i]);
        }
        printf(" | %d\n", j);
    }*/

    // release all resources
    free(rule_ip);
    free(rule_mask);
    free(rule_protocol);
    free(rule_s_port);
    free(rule_d_port);
    free(rule_verdict);
    release_buffer(&program, &context);
}