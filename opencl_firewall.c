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

// custom headers
#include "variables.h"
#include "compare.h"
#include "rule_loader.h"

struct ruleAttributes
{
    uint64_t *ip;
    uint64_t *mask;
    uint8_t *protocol;
    uint16_t *s_port;
    uint16_t *d_port;
    int *verdict;
};

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
    /*a packet buffer may needs to be implemented
    if it turns out libnetfilter_queue doesn't hold the packet*/
};

// file global for libnetfilter_queue
long int packet_count = 0;
long int batch_num = 0;
int netf_fd;
char buf[0xffff] __attribute__((aligned));
struct nfq_handle *handler;

// file global for storing packet
struct callbackStruct *packet_data[queue_num];
struct callbackStruct *packet_data_tail[queue_num];
static pthread_mutex_t packet_data_mtx[queue_num];
static volatile int packet_data_count[queue_num];

// file global for OpenCL kernel
struct ipv4Rule *ruleList = NULL;
static int ruleNum;
/*uint64_t *rule_ip = NULL;
uint64_t *rule_mask = NULL;
uint8_t *rule_protocol = NULL;
uint16_t *rule_s_port = NULL;
uint16_t *rule_d_port = NULL;
int *rule_verdict = NULL;*/
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
        err = pthread_mutex_lock(&packet_data_mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_lock fails\n");
            exit(1);
        }
        packet_data[queueNum] = localBuff;
        packet_data_tail[queueNum] = localBuff;
        packet_data_count[queueNum]++;
        err = pthread_mutex_unlock(&packet_data_mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_unlock fails\n");
            exit(1);
        }
    }
    else if (!packet_data_tail[queueNum]->next)
    {
        err = pthread_mutex_lock(&packet_data_mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_lock fails\n");
            exit(1);
        }
        packet_data_tail[queueNum]->next = localBuff;
        packet_data_tail[queueNum] = packet_data_tail[queueNum]->next;
        packet_data_count[queueNum]++;
        err = pthread_mutex_unlock(&packet_data_mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_unlock fails\n");
            exit(1);
        }
    }
    else
    {
        err = pthread_mutex_lock(&packet_data_mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_lock fails\n");
            exit(1);
        }
        lastBuff = packet_data[queueNum];

        // what if lastBuff is freed by verdictThread before finding next?
        while (lastBuff->next != NULL)
        {
            lastBuff = lastBuff->next;
        }
        lastBuff->next = localBuff;
        packet_data_tail[queueNum] = localBuff;
        packet_data_count[queueNum]++;
        err = pthread_mutex_unlock(&packet_data_mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_unlock fails\n");
            exit(1);
        }
    }

    return 0;
}

// takes data stored by callback and calls OpenCL kernel
void *verdictThread(void *args)
{
    struct ruleAttributes *rule = (struct ruleAttributes *)args;

    uint64_t *rule_ip = (*rule).ip;
    uint64_t *rule_mask = (*rule).mask;
    uint8_t *rule_protocol = (*rule).protocol;
    uint16_t *rule_s_port = (*rule).s_port;
    uint16_t *rule_d_port = (*rule).d_port;
    int *rule_verdict = (*rule).verdict;

    int err;
    uint32_t ip_addr[2] __attribute__((aligned));
    // uint16_t sPort, dPort;
    // uint8_t protocol;
    struct callbackStruct *tempNode = NULL;
    uint64_t array_ip_input[ip_array_size];
    uint8_t protocol_input[ip_array_size];
    uint16_t s_port_input[ip_array_size], d_port_input[ip_array_size];
    uint64_t array_ip_input_buff[queue_num][queue_multipler];
    uint8_t protocol_input_buff[queue_num][queue_multipler];
    uint16_t s_port_input_buff[queue_num][queue_multipler], d_port_input_buff[queue_num][queue_multipler];

    // waits for packets to arrive in ALL queues
    while (1)
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

    while (1)
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

        printf("\n");
        for (int i = 0; i < ruleNum; i++)
        {
            // printf("RULE s %d %u.%u.%u.%u d %u.%u.%u.%u proto %d sp %u dp %u\n", i, printable_ip_joined(rule_ip[i]), rule_protocol[i], rule_s_port[i], rule_d_port[i]);
            printf("RULE proto %d sp %u dp %u\n", rule_protocol[i], rule_s_port[i], rule_d_port[i]);
        }

        for (int i = 0; i < queue_num; i++)
        {
            tempNode = packet_data[i];
            for (int j = 0; j < queue_multipler; j++)
            {
                // source and dest ip and masks are concatenated to 64 bits
                ip_addr[0] = tempNode->source_ip;
                ip_addr[1] = tempNode->dest_ip;
                // protocol = tempNode->ip_protocol;
                // sPort = tempNode->source_port;
                // dPort = tempNode->dest_port;
                // protocol = tempNode->ip_protocol;
                printf("QUEUE %d PACKET ID: %u\n", i, tempNode->packet_id);
                printf("s %u.%u.%u.%u d %u.%u.%u.%u proto %u sp %u dp %u\n", printable_ip(ip_addr[0]), printable_ip(ip_addr[1]), tempNode->ip_protocol, tempNode->source_port, tempNode->dest_port);

                memcpy(&array_ip_input_buff[i][j], ip_addr, 8);
                protocol_input_buff[i][j] = tempNode->ip_protocol;
                s_port_input_buff[i][j] = tempNode->source_port;
                d_port_input_buff[i][j] = tempNode->dest_port;
                tempNode = tempNode->next;
            }
        }

        // can be removed and write to 2d array and read as 1d from opencl when match on cpu is removed
        memcpy(array_ip_input, array_ip_input_buff, ip_array_size * 8);
        memcpy(protocol_input, protocol_input_buff, ip_array_size * 1);
        memcpy(s_port_input, s_port_input_buff, ip_array_size * 2);
        memcpy(d_port_input, d_port_input_buff, ip_array_size * 2);
        // check rule_ip ip on cpu, can be removed later
        int test,
            protocol_result, sport_result, dport_result;
        int verdict_buffer = 0;

        printf("\n");
        for (int i = 0; i < ip_array_size; i++)
        {
            printf("sIP %u.%u.%u.%u dIP %u.%u.%u.%u\n", printable_ip_joined(array_ip_input[i]));
            printf("Proto %u sPort %u dPort %u\n", protocol_input[i], s_port_input[i], d_port_input[i]);
        }

        printf("MATCH ON CPU\n");
        for (int i = 0; i < ip_array_size * ruleNum; i++)
        {

            printf("AAAAAAAA\n");
            /*if (rule_protocol[i % ruleNum] == 0)
            {
                protocol_input[i / ruleNum] = 0;
            }
            if (rule_s_port[i % ruleNum] == 0)
            {
                s_port_input[i / ruleNum] = 0;
            }
            if (rule_d_port[i % ruleNum] == 0)
            {
                d_port_input[i / ruleNum] = 0;
            }*/
            test = rule_ip[i % ruleNum] == (array_ip_input[i / ruleNum] & rule_mask[i % ruleNum]);
            protocol_result = (rule_protocol[i % ruleNum] == protocol_input[i / ruleNum]);
            sport_result = (rule_s_port[i % ruleNum] == s_port_input[i / ruleNum]);
            dport_result = (rule_d_port[i % ruleNum] == d_port_input[i / ruleNum]);
            //        printf("%d|", i / ruleNum);
            //        printf("%u.%u.%u.%u\n", printable_ip(array_ip_input[i/ruleNum]));
            /*if (test == 1)
            {
                verdict_buffer = rule_verdict[i % ruleNum];
                i += ruleNum - i % ruleNum;
                printf("%d", verdict_buffer);
                verdict_buffer = 0;
            }
            if (i % ruleNum == ruleNum - 1)
            {
                printf("%d", verdict_buffer);
                verdict_buffer = 0;
            }*/

            printf("Input IP %u.%u.%u.%u Proto %u sPort %u dPort %u\n", printable_ip(array_ip_input[i / ruleNum]), protocol_input[i / ruleNum], s_port_input[i / ruleNum], d_port_input[i / ruleNum]);
            printf("Rule IP %u.%u.%u.%u Proto %u sPort %u dPort %u\n", printable_ip(rule_ip[i % ruleNum]), rule_protocol[i % ruleNum], rule_s_port[i % ruleNum], rule_d_port[i % ruleNum]);
            printf("IP Match %d Proto Match %d sPort Match %d dPort Match %d\n", test, protocol_result, sport_result, dport_result);
        }
        printf("\n");

        /*printf("MATCH ON OPENCL DEVICE\n");
        compare(array_ip_input, s_port_input, d_port_input, protocol_input, rule_ip, rule_mask, rule_s_port, rule_d_port, rule_protocol, rule_verdict, result, ip_array_size, ruleNum);
        */
        for (int i = 0; i < queue_num; i++)
        {
            for (int j = 0; j < queue_multipler; j++)
            {
                // printf("%d", result[i * queue_multipler + j]);
                //  nfq_set_verdict(packet_data[i]->queue, packet_data[i]->packet_id, result[i * queue_multipler + j], 0, NULL);
                nfq_set_verdict(packet_data[i]->queue, packet_data[i]->packet_id, NF_ACCEPT, 0, NULL);

                err = pthread_mutex_lock(&packet_data_mtx[i]);
                if (err != 0)
                {
                    fprintf(stderr, "pthread_mutex_lock fails\n");
                    exit(1);
                }
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
                err = pthread_mutex_unlock(&packet_data_mtx[i]);
                if (err != 0)
                {
                    fprintf(stderr, "pthread_mutex_unlock fails\n");
                    exit(1);
                }
            }
        }

        /*for (int i = 0; i < ip_array_size; i++)
        {
            printf("IP %u.%u.%u.%u\n", printable_ip(array_ip_input[i]));
            printf("Proto %u sPort %u dPort %u\n", protocol_input[i], s_port_input[i], d_port_input[i]);
        }*/
    }
}

// connect to libnetfilter_queue via recv, could this be a bottleneck?
void *recvThread()
{
    int rcv_len;

    while (1)
    {
        rcv_len = recv(netf_fd, buf, sizeof(buf), 0);
        if (rcv_len < 0)
            continue;
        nfq_handle_packet(handler, buf, rcv_len);
    }
    return 0;
}

int prep_rules(uint64_t *rule_ip, uint64_t *rule_mask, uint8_t *rule_protocol, uint16_t *rule_s_port, uint16_t *rule_d_port, int *rule_verdict)
{
    uint32_t *sAddr, *dAddr, *sMask, *dMask, mergeBuff[2] __attribute__((aligned));
    uint16_t *sPort, *dPort;

    ruleList = malloc(sizeof(struct ipv4Rule));
    ruleNum = load_rules(rule_file, ruleList);

    // local buffers used to load rules
    sAddr = malloc(ruleNum * 4);
    dAddr = malloc(ruleNum * 4);
    sMask = malloc(ruleNum * 4);
    dMask = malloc(ruleNum * 4);
    sPort = malloc(ruleNum * 2);
    dPort = malloc(ruleNum * 2);

    printf("Number of rules %d\n", ruleNum);
    rule_list_to_arr(ruleList, sAddr, sMask, dAddr, dMask, rule_protocol, sPort, dPort, rule_verdict);
    free_rule_list(ruleList);

    /*loading procedure may be redundant but easier to modify if OpenCL arg size change, such as merging source and dest ip*/

    for (int i = 0; i < ruleNum; i++)
    {
        printf("RULE %d %u.%u.%u.%u d %u.%u.%u.%u proto %d sp %u dp %u\n", i, printable_ip(sAddr[i]), printable_ip(dAddr[i]), rule_protocol[i], sPort[i], dPort[i]);
        mergeBuff[0] = sAddr[i];
        mergeBuff[1] = dAddr[i];
        memcpy(&rule_ip[i], mergeBuff, 8);
        mergeBuff[0] = sMask[i];
        mergeBuff[1] = dMask[i];
        memcpy(&rule_mask[i], mergeBuff, 8);
    }
    memcpy(rule_s_port, sPort, ruleNum * 2);
    memcpy(rule_d_port, dPort, ruleNum * 2);

    // free  local buffers
    free(sAddr);
    free(dAddr);
    free(sMask);
    free(dMask);
    free(sPort);
    free(dPort);
    return 0;
}

// only functions to load the programm
int main()
{
    struct nfq_q_handle *queue[queue_num];
    pthread_t vt, rt;
    int queueNum[queue_num];
    struct callbackStruct *tempNode;
    struct ruleAttributes *rule = malloc(sizeof(struct ruleAttributes));

    rule->ip = malloc(ruleNum * 8);
    rule->mask = malloc(ruleNum * 8);
    rule->protocol = malloc(ruleNum);
    rule->s_port = malloc(ruleNum * 2);
    rule->d_port = malloc(ruleNum * 2);
    rule->verdict = malloc(ruleNum * sizeof(int));
    prep_rules(rule->ip, rule->mask, rule->protocol, rule->s_port, rule->d_port, rule->verdict);

    /*printf("\nFROM MAIN\n");
    for (int i = 0; i < ruleNum; i++)
    {
        printf("RULE %d s %u.%u.%u.%u d %u.%u.%u.%u proto %d sp %u dp %u\n", i, printable_ip_joined(rule_ip[i]), rule_protocol[i], rule_s_port[i], rule_d_port[i]);
    }*/

    for (int i = 0; i < ip_array_size; i++)
    {
        packet_data[i] = NULL;
        packet_data_tail[i] = NULL;
        packet_data_mtx[i] = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
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
    }

    netf_fd = nfq_fd(handler);
    pthread_create(&rt, NULL, recvThread, NULL);
    pthread_create(&vt, NULL, verdictThread, (void *)rule);

    // need to turn this to a daemon
    while (1)
    {
        continue;
    }

    // clean up queues
    pthread_cancel(rt);
    pthread_cancel(vt);

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

    // free rule arrays
    free(rule->ip);
    free(rule->mask);
    free(rule->verdict);
    free(rule->protocol);
    free(rule->s_port);
    free(rule->d_port);
    free(rule);
    return 0;
}