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

// struct to store packet data from callback
struct callbackStruct
{
    struct nfq_q_handle *queue;
    struct nfq_data *nfad;
    struct callbackStruct *next;
    uint32_t source_ip;
    uint32_t dest_ip;
    uint32_t packet_id;

    uint8_t ip_protocol;
    uint16_t source_port;
    uint16_t dest_port;
};

// file global for thread loops
volatile int recv_running = 1, verdict_running = 1;

// file global for libnetfilter_queue
long int packet_count = 0;
long int batch_num = 0;
int netf_fd;
char buf[0xffff] __attribute__((aligned));
struct nfq_handle *handler;

// file global for storing packet
struct callbackStruct *packet_data[queue_num];
struct callbackStruct *packet_data_tail[queue_num];
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
    struct callbackStruct *localBuff, *lastBuff;
    unsigned char *rawData;
    struct pkt_buff *pkBuff;
    struct iphdr *ip;
    struct nfqnl_msg_packet_hdr *ph;
    struct tcphdr *tcp;
    struct udphdr *udp;
    // uint32_t source_ip, dest_ip;

    localBuff = malloc(sizeof(struct callbackStruct));
    lastBuff = NULL;

    localBuff->nfad = malloc(sizeof(nfad));

    localBuff->queue = queue;

    memcpy(localBuff->nfad, nfad, sizeof(nfad));
    localBuff->next = NULL;

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

    localBuff->source_ip = ntohl(ip->saddr);
    localBuff->dest_ip = ntohl(ip->daddr);
    localBuff->packet_id = ntohl(ph->packet_id);
    localBuff->ip_protocol = ip->protocol;

    if (nfq_ip_set_transport_header(pkBuff, ip) < 0)
    {
        localBuff->source_port = 0;
        localBuff->dest_port = 0;
    }
    else if (ip->protocol == IPPROTO_TCP)
    {
        tcp = nfq_tcp_get_hdr(pkBuff);
        if (!tcp)
        {
            localBuff->source_port = 0;
            localBuff->dest_port = 0;
        }
        else
        {
            localBuff->source_port = ntohs(tcp->source);
            localBuff->dest_port = ntohs(tcp->dest);
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
            localBuff->source_port = ntohs(udp->source);
            localBuff->dest_port = ntohs(udp->dest);
        }
    }
    else
    {
        localBuff->source_port = 0;
        localBuff->dest_port = 0;
    }

    pktb_free(pkBuff);

    if (!packet_data[queueNum])
    {
        packet_data[queueNum] = localBuff;
        packet_data_tail[queueNum] = localBuff;
        packet_data_count[queueNum]++;
    }
    else if (!packet_data_tail[queueNum]->next)
    {
        packet_data_tail[queueNum]->next = localBuff;
        packet_data_tail[queueNum] = packet_data_tail[queueNum]->next;
        packet_data_count[queueNum]++;
    }
    else
    {
        // do we even need this case?
        /*err = pthread_mutex_lock(&packet_data_mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_lock fails\n");
            exit(1);
        }*/
        lastBuff = packet_data[queueNum];

        // what if lastBuff is freed by verdictThread before finding next?
        while (lastBuff->next != NULL)
        {
            lastBuff = lastBuff->next;
        }
        lastBuff->next = localBuff;
        packet_data_tail[queueNum] = localBuff;
        packet_data_count[queueNum]++;
        /*err = pthread_mutex_unlock(&packet_data_mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_unlock fails\n");
            exit(1);
        }*/
    }

    return 0;
}

// takes data stored by callback and calls OpenCL kernel
void *verdictThread()
{

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

    // packet data buffers
    int mutex_err;
    uint32_t ip_addr[2] __attribute__((aligned));
    struct callbackStruct *tempNode = NULL;

    uint64_t array_ip_input[queue_num][queue_multipler];
    uint8_t protocol_input[queue_num][queue_multipler];
    uint16_t s_port_input[queue_num][queue_multipler], d_port_input[queue_num][queue_multipler];

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

    // prep opencl buffers
    deviceId = create_device_cl();
    // create context
    context = clCreateContext(NULL, 1, &deviceId, NULL, NULL, &ocl_err);
    print_err(ocl_err);

    // build program;
    program = create_program_cl(context, deviceId, source);

    // create all buffer Rule(with value) and input
    declare_buffer(&context, rule_ip, rule_mask, rule_s_port, rule_d_port, rule_protocol, rule_verdict, ruleNum, ip_array_size);

    // waits for packets to arrive in ALL queues
    while (verdict_running)
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

    while (verdict_running)
    {
        for (int i = 0; i < queue_num; i++)
        {
            // makes sure each queue has enough packets, perhaps can be optimised?
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

                memcpy(&array_ip_input[i][j], ip_addr, 8);
                protocol_input[i][j] = tempNode->ip_protocol;
                s_port_input[i][j] = tempNode->source_port;
                d_port_input[i][j] = tempNode->dest_port;
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
                if (packet_data[i]->next)
                {
                    tempNode = NULL;

                    tempNode = packet_data[i];
                    packet_data[i] = packet_data[i]->next;
                    tempNode->queue = NULL;
                    free(tempNode->nfad);
                    free(tempNode);
                    packet_data_count[i]--;
                }
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
    verdict_running = -1;
}

// connect to libnetfilter_queue via recv, could this be a bottleneck?
void *recvThread()
{
    int rcv_len;

    while (recv_running)
    {
        rcv_len = recv(netf_fd, buf, sizeof(buf), 0);
        if (rcv_len < 0)
            continue;
        nfq_handle_packet(handler, buf, rcv_len);
    }
    recv_running = -1;
    return 0;
}

// only functions to load the programm
int main()
{
    struct nfq_q_handle *queue[queue_num];
    pthread_t vt, rt;
    int queueNum[queue_num];
    struct callbackStruct *tempNode;

    for (int i = 0; i < queue_num; i++)
    {
        packet_data[i] = NULL;
        packet_data_tail[i] = NULL;
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
    pthread_create(&rt, NULL, recvThread, NULL);
    pthread_create(&vt, NULL, verdictThread, NULL);

    // need to turn this to a daemon
    while (1)
    {
        continue;
    }

    // clean up queues
    recv_running = 0;
    pthread_join(rt, NULL);
    verdict_running = 0;
    pthread_join(vt, NULL);

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