// c and linux headers
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <linux/types.h>

// nfq headers
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>

// opencl headers
#include <CL/cl.h>

// custom headers
#include "variables.h"
#include "rule_loader.h"
#include "src/src.h"

// file global for thread loops
volatile int program_running = 1;

// file global for libnetfilter_queue
long int packet_count = 0;
long int batch_num = 0;
int netf_fd;
char buf[0xffff] __attribute__((aligned));
struct nfq_handle *handler;

// file global for storing packet
/*struct callbackStruct *packet_data[queue_num];
struct callbackStruct *packet_data_tail[queue_num];
static pthread_mutex_t packet_data_mtx[queue_num];*/
uint64_t array_ip_input[ip_array_size];
uint32_t packet_id[ip_array_size];
uint8_t protocol_input[ip_array_size];
uint16_t s_port_input[ip_array_size], d_port_input[ip_array_size];
static volatile int packet_data_count[queue_num];

// file global for OpenCL kernel
struct ipv4Rule *ruleList = NULL;
static int ruleNum;
int result[ip_array_size];

// callback function for libnetfilter_queue
static int
netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    int queueNum, rcv_len, err;
    unsigned char *rawData;
    struct pkt_buff *pkBuff;
    struct iphdr *ip;
    struct nfqnl_msg_packet_hdr *ph;
    struct tcphdr *tcp;
    struct udphdr *udp;
    uint32_t ip_addr[2];

    memcpy(&queueNum, (int *)data, sizeof(int));
    // printf("QUEUE NUM %d PACKET NUM %d\n", queueNum, packetNumInQ[queueNum] + 1);

    ph = nfq_get_msg_packet_hdr(nfad);
    if (!ph)
    {
        return 0;
    }

    rawData = NULL;
    // get packet data from nfad
    rcv_len = nfq_get_payload(nfad, &rawData);
    if (rcv_len < 0)
    {
        nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
        return 0;
    }

    // allocate user space buffer???
    pkBuff = pktb_alloc(AF_INET, rawData, rcv_len, 0x1000);
    if (!pkBuff)
    {
        nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
        return 0;
    }

    ip = nfq_ip_get_hdr(pkBuff);
    if (!ip)
    {
        nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
        return 0;
    }

    memcpy(&array_ip_input[queueNum * queue_multipler + packet_data_count[queue_num]], ip_addr, 8);
    s_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = ip->protocol;
    packet_id[queueNum * queue_multipler + packet_data_count[queue_num]] = ntohl(ph->packet_id);

    if (nfq_ip_set_transport_header(pkBuff, ip) < 0)
    {
        s_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = 0;
        d_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = 0;
    }
    else if (ip->protocol == IPPROTO_TCP)
    {
        tcp = nfq_tcp_get_hdr(pkBuff);
        if (!tcp)
        {
            s_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = 0;
            d_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = 0;
        }
        else
        {
            s_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = ntohs(tcp->source);
            d_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = ntohs(tcp->dest);
        }
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        udp = nfq_udp_get_hdr(pkBuff);
        if (!udp)
        {
            localBuff->source_port = 0;
            localBuff->dest_port = 0;
        }
        else
        {
            s_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = ntohs(udp->source);
            d_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = ntohs(udp->dest);
        }
    }
    else
    {
        s_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = 0;
        d_port_input[queueNum * queue_multipler + packet_data_count[queue_num]] = 0;
    }

    pktb_free(pkBuff);

    packet_data_count[queue_num]++;

    return 0;
}

// takes data stored by callback and calls OpenCL kernel
void *verdictThread()
{

    // waits for packets to arrive in ALL queues
    while (program_running)
    {
        for (int i = 0; i < queue_num; i++)
        {
            if (packet_data_count[i] < queue_multipler + 1)
            {
                goto cnt;
            }
        }

        break;

    cnt:;
        continue;
    }

    while (program_running)
    {
        for (int i = 0; i < queue_num; i++)
        {
            // makes sure each queues has at least 2 packets, perhaps can be optimised?
            if (packet_data_count[i] < queue_multipler + 1)
            {
                goto cnt;
            }
        }

        printf("\n\n\nSTARTING OCL PREP %ld\n\n\n", ++batch_num);

        for (int i = 0; i < queue_num; i++)
        {
            tempNode = packet_data[i];
            for (int j = 0; j < queue_multipler; j++)
            {
                // source and dest ip and masks are concatenated to 64 bits
                ip_addr[0] = tempNode->source_ip;
                ip_addr[1] = tempNode->dest_ip;
                printf("QUEUE %d PACKET ID: %u\n", i, tempNode->packet_id);
                printf("s %u.%u.%u.%u d %u.%u.%u.%u proto %u sp %u dp %u\n", printable_ip(ip_addr[0]), printable_ip(ip_addr[1]), tempNode->ip_protocol, tempNode->source_port, tempNode->dest_port);

                memcpy(&array_ip_input_buff[i][j], ip_addr, 8);
                protocol_input_buff[i][j] = tempNode->ip_protocol;
                s_port_input_buff[i][j] = tempNode->source_port;
                d_port_input_buff[i][j] = tempNode->dest_port;
                tempNode = tempNode->next;
            }
        }

        printf("MATCH ON OPENCL DEVICE\n");
        compare(array_ip_input, s_port_input, d_port_input, protocol_input, &deviceId, &context, &program, result, ip_array_size, ruleNum);
        for (int i = 0; i < queue_num; i++)
        {
            for (int j = 0; j < queue_multipler; j++)
            {
                printf("%d", result[i * queue_multipler + j]);
                nfq_set_verdict(packet_data[i]->queue, packet_data[i]->packet_id, result[i * queue_multipler + j], 0, NULL);
            }
        }
    }
    release_buffer(&program, &context);
    free(rule_ip);
    free(rule_mask);
    free(rule_protocol);
    free(rule_s_port);
    free(rule_d_port);
    free(rule_verdict);
}

// only functions to load the programm
int main()
{
    struct nfq_q_handle *queue[queue_num];
    pthread_t vt, rt;
    int queueNum[queue_num];
    struct callbackStruct *tempNode;

    int rcv_len;

    // local opencl variables
    cl_device_id deviceId;
    cl_context context;
    cl_program program;
    cl_int ocl_err;

    // rules buffers
    uint64_t *rule_ip;
    uint64_t *rule_mask;
    uint8_t *rule_protocol;
    uint16_t *rule_s_port;
    uint16_t *rule_d_port;
    int *rule_verdict;

    // prep rules
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

    for (int i = 0; i < ruleNum; i++)
    {
        printf("RULE %d %u.%u.%u.%u d %u.%u.%u.%u proto %d sp %u dp %u\n", i, printable_ip_joined(rule_ip[i]), rule_protocol[i], rule_s_port[i], rule_d_port[i]);
    }

    for (int i = 0; i < queue_num; i++)
    {
        packet_data_count[i] = 0;
    }

    handler = nfq_open();

    if (!handler)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    // unbinding existing nf_queue handler for AF_INET (if any)
    if (nfq_unbind_pf(handler, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    // binding nfnetlink_queue as nf_queue handler for AF_INET
    if (nfq_bind_pf(handler, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    for (int i = 0; i < queue_num; i++)
    {
        queueNum[i] = i;
        queue[i] = nfq_create_queue(handler, i, netfilterCallback, &queueNum[i]);
        if (!queue[i])
        {
            fprintf(stderr, "error during nfq_create_queue()\n");
            exit(1);
        }

        if (nfq_set_mode(queue[i], NFQNL_COPY_PACKET, 0xffff) < 0)
        {
            fprintf(stderr, "can't set packet_copy mode\n");
            exit(1);
        }
        if (nfq_set_queue_maxlen(queue[i], (uint32_t)0xffffffff) < 0)
        {
            fprintf(stderr, "can't set queue maxlen\n");
            exit(1);
        }
    }

    netf_fd = nfq_fd(handler);

    // prep opencl buffers
    deviceId = create_device_cl();
    // create context
    context = clCreateContext(NULL, 1, &deviceId, NULL, NULL, &ocl_err);
    print_err(ocl_err);

    // build program;
    program = create_program_cl(context, deviceId, source);

    // create all buffer Rule(with value) and input
    declare_buffer(&context, rule_ip, rule_mask, rule_s_port, rule_d_port, rule_protocol, rule_verdict, result, ruleNum, ip_array_size);

    // need to turn this to a daemon
    while (program_running)
    {
        rcv_len = recv(netf_fd, buf, sizeof(buf), 0);
        if (rcv_len < 0)
            continue;
        nfq_handle_packet(handler, buf, rcv_len);
        continue;
    }

    // clean up queues

    for (int i = 0; i < queue_num; i++)
    {
        nfq_destroy_queue(queue[i]);
    }

    nfq_close(handler);

    // clean up stored packet data
    for (int i = 0; i < queue_num; i++)
    {
        tempNode = packet_data[i];
        if (!tempNode)
        {
            continue;
        }
        while (tempNode->next != NULL)
        {
            tempNode = tempNode->next;
            free(packet_data[i]);
            packet_data[i] = tempNode;
        }
    }

    return 0;
}