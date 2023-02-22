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

#include "variables.h"
#include "compare.h"
#include "rule_loader.h"

long int packet_count = 0;
long int batch_num = 0;
int netf_fd;
char buf[0xffff] __attribute__((aligned));
struct nfq_handle *handler;

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

struct callbackStruct *callbackStructArray[ip_array_size];
struct callbackStruct *tailArray[ip_array_size];
static pthread_mutex_t mtx[ip_array_size];
static int packetNumInQ[ip_array_size];

struct ipv4Rule *ruleList = NULL;
int ruleNum;
uint64_t *rule_ip = NULL;
uint64_t *mask = NULL;
uint8_t *rule_protocol = NULL;
uint16_t *rule_s_port = NULL;
uint16_t *rule_d_port = NULL;
int *rule_verdict = NULL;

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

    /*source_ip = ntohl(ip->saddr);
    dest_ip = ntohl(ip->daddr);*/

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

    if (!callbackStructArray[queueNum])
    {
        err = pthread_mutex_lock(&mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_lock fails\n");
            exit(1);
        }
        callbackStructArray[queueNum] = localBuff;
        tailArray[queueNum] = localBuff;
        packetNumInQ[queueNum]++;
        err = pthread_mutex_unlock(&mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_unlock fails\n");
            exit(1);
        }
    }
    else if (!tailArray[queueNum]->next)
    {
        err = pthread_mutex_lock(&mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_lock fails\n");
            exit(1);
        }
        tailArray[queueNum]->next = localBuff;
        tailArray[queueNum] = tailArray[queueNum]->next;
        packetNumInQ[queueNum]++;
        err = pthread_mutex_unlock(&mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_unlock fails\n");
            exit(1);
        }
    }
    else
    {
        // could this be causing trouble?
        err = pthread_mutex_lock(&mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_lock fails\n");
            exit(1);
        }
        lastBuff = callbackStructArray[queueNum];

        // what if lastBuff is freed by verdictThread before finding next?
        while (lastBuff->next != NULL)
        {
            lastBuff = lastBuff->next;
        }
        lastBuff->next = localBuff;
        tailArray[queueNum] = localBuff;
        packetNumInQ[queueNum]++;
        err = pthread_mutex_unlock(&mtx[queueNum]);
        if (err != 0)
        {
            fprintf(stderr, "pthread_mutex_unlock fails\n");
            exit(1);
        }
    }

    return 0;
}

void *verdictThread()
{
    int err;
    // uint32_t source_ip, dest_ip;
    uint32_t ip_addr[2] __attribute__((aligned));
    uint16_t sPort, dPort;
    uint8_t protocol;
    struct callbackStruct *tempNode;
    uint64_t array_ip_input[ip_array_size];
    uint8_t protocol_input[ip_array_size];
    uint16_t s_port_input[ip_array_size], d_port_input[ip_array_size];

    while (1)
    {
        for (int i = 0; i < ip_array_size; i++)
        {
            if (!(callbackStructArray[i]))
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
        for (int i = 0; i < ip_array_size; i++)
        {
            if (!(callbackStructArray[i]))
            {
                goto cnt;
            }

            if (!(callbackStructArray[i]->next))
            {
                goto cnt;
            }
        }

        printf("\n\n\nSTARTING OCL PREP %ld\n\n\n", ++batch_num);

        for (int i = 0; i < ip_array_size; i++)
        {
            ip_addr[0] = callbackStructArray[i]->source_ip;
            ip_addr[1] = callbackStructArray[i]->dest_ip;
            protocol = callbackStructArray[i]->ip_protocol;
            sPort = callbackStructArray[i]->source_port;
            dPort = callbackStructArray[i]->dest_port;
            protocol = callbackStructArray[i]->ip_protocol;
            // printf("Q: %p NFAD %p\n", callbackStructArray[i]->queue, callbackStructArray[i]->nfad);
            printf("QUEUE %d PACKET ID: %u\n", i, callbackStructArray[i]->packet_id);
            printf("s %u.%u.%u.%u d %u.%u.%u.%u proto %u sp %u dp %u\n", printable_ip(ip_addr[0]), printable_ip(ip_addr[1]), protocol, sPort, dPort);

            // array_ip_input[i] = source_ip;
            memcpy(&array_ip_input[i], ip_addr, 8);
            protocol_input[i] = protocol;
            s_port_input[i] = sPort;
            d_port_input[i] = dPort;
        }

        // check rule_ip ip on cpu
        printf("MATCH ON CPU\n");
        bool test;
        for (int i = 0; i < rule_array_size; i++)
        {
            printf("%s %d: SOURCE : %u.%u.%u.%u Mask : %u.%u.%u.%u DEST : %u.%u.%u.%u Mask : %u.%u.%u.%u | verdict : %d\n", "Rule no.", i, printable_ip(rule_ip[i]), printable_ip(mask[i]), printable_ip(rule_ip[i] + 4), printable_ip(mask[i] + 4), rule_verdict[i]);
        }
        for (int i = 0; i < ip_array_size * rule_array_size; i++)
        {
            test = rule_ip[i % rule_array_size] == (array_ip_input[i / rule_array_size] & mask[i % rule_array_size]);
            printf("%d", test);
            //        printf(" | %u.%u.%u.%u ", printable_ip(array_ip_input[i/rule_array_size]));
            if (i % rule_array_size == rule_array_size - 1)
            {
                printf("\n");
            }
        }

        printf("MATCH ON DEVICE\n");
        compare(array_ip_input, s_port_input, d_port_input, protocol_input, rule_ip, mask, rule_s_port, rule_d_port, rule_protocol, rule_verdict, result, ip_array_size, ruleNum);
        for (int i = 0; i < sizeof(result) / sizeof(int); i++)
        {
            printf("%d", result[i]);
            nfq_set_verdict(callbackStructArray[i]->queue, callbackStructArray[i]->packet_id, result[i], 0, NULL);
            err = pthread_mutex_lock(&mtx[i]);
            if (err != 0)
            {
                fprintf(stderr, "pthread_mutex_lock fails\n");
                exit(1);
            }
            if (callbackStructArray[i]->next)
            {
                tempNode = NULL;

                tempNode = callbackStructArray[i];
                callbackStructArray[i] = callbackStructArray[i]->next;
                tempNode->queue = NULL;
                free(tempNode->nfad);
                free(tempNode);
                packetNumInQ[i]--;
            }
            err = pthread_mutex_unlock(&mtx[i]);
            if (err != 0)
            {
                fprintf(stderr, "pthread_mutex_unlock fails\n");
                exit(1);
            }
        }
    }
}

void *recvThread()
{
    int rcv_len;

    while (1)
    {
        rcv_len = recv(netf_fd, buf, sizeof(buf), 0);
        if (rcv_len < 0)
            continue;
        // printf("pkt received %ld\n", ++packet_count);
        nfq_handle_packet(handler, buf, rcv_len);
    }
    return 0;
}

int main()
{
    struct nfq_q_handle *queue[ip_array_size];
    pthread_t vt, rt;
    int queueNum[ip_array_size];
    struct callbackStruct *tempNode;
    unsigned char string_ip[4];
    uint32_t *sAddr, *dAddr, *sMask, *dMask, mergeBuff[2];
    uint16_t *sPort, *dPort;

    ruleList = malloc(sizeof(struct ipv4Rule));
    ruleNum = load_rules(ruleFileName, ruleList);

    rule_ip = malloc(ruleNum * 8);
    mask = malloc(ruleNum * 8);
    rule_protocol = malloc(ruleNum);
    rule_s_port = malloc(ruleNum * 2);
    rule_d_port = malloc(ruleNum * 2);
    rule_verdict = malloc(ruleNum * sizeof(int));

    // local buffers used to load rules
    sAddr = malloc(ruleNum * 4);
    dAddr = malloc(ruleNum * 4);
    sMask = malloc(ruleNum * 4);
    dMask = malloc(ruleNum * 4);
    sPort = malloc(ruleNum * 2);
    dPort = malloc(ruleNum * 2);

    printf("Number of rules %d\n", ruleNum);
    ruleListToArr(ruleList, sAddr, sMask, dAddr, dMask, rule_protocol, sPort, dPort, rule_verdict);
    /*for (int i = 0; i < ruleNum; i++)
    {
        printf("SOURCE : %u.%u.%u.%u Mask : %u.%u.%u.%u DEST : %u.%u.%u.%u Mask : %u.%u.%u.%u Verdict: %d\n", printable_ip(sAddr[i]), printable_ip(sMask[i]), printable_ip(dAddr[i]), printable_ip(dMask[i]), tempVerdict[i]);
    }*/
    freeRules(ruleList);

    /*loading procedure may be redundant but easier to modify if OpenCL arg size change, such as merging source and dest ip*/
    for (int i = 0; i < rule_array_size; i++)
    {
        mergeBuff[0] = sAddr[i];
        mergeBuff[1] = dAddr[i];
        memcpy(&rule_ip[i], mergeBuff, 8);
        mergeBuff[0] = sMask[i];
        mergeBuff[1] = dMask[i];
        memcpy(&mask[i], mergeBuff, 8);
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

    for (int i = 0; i < ip_array_size; i++)
    {
        callbackStructArray[i] = NULL;
        tailArray[i] = NULL;
        mtx[i] = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
        packetNumInQ[i] = 0;
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

    for (int i = 0; i < ip_array_size; i++)
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
    pthread_create(&vt, NULL, verdictThread, NULL);

    // need to turn this to a daemon
    while (1)
    {
        continue;
    }

    // clean up queues
    pthread_cancel(rt);
    pthread_cancel(vt);
    nfq_close(handler);

    // clean up stored packet data
    for (int i = 0; i < ip_array_size; i++)
    {
        nfq_destroy_queue(queue[i]);
        tempNode = callbackStructArray[i];
        if (!tempNode)
        {
            continue;
        }
        while (tempNode->next != NULL)
        {
            tempNode = tempNode->next;
            free(callbackStructArray[i]);
            callbackStructArray[i] = tempNode;
        }
    }

    // free rule arrays
    free(rule_ip);
    free(mask);
    free(rule_verdict);
    free(rule_protocol);
    free(rule_s_port);
    free(rule_d_port);
    return 0;
}