#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#define ip_array_size 5

long int packet_count = 0;
int netf_fd;
char buf[0xffff] __attribute__((aligned));
struct nfq_handle *handler;

// what if we can use pkt_buff instead
struct callbackStruct
{
    // pointer to queue which packet is stored
    struct nfq_q_handle *queue;

    // pointer to packet data in queue, not sure where it is stored
    struct nfq_data *nfad;
    struct callbackStruct *next;
    uint32_t source_ip;
    uint32_t dest_ip;
    uint32_t packet_id;
};

struct callbackStruct *callbackStructArray[ip_array_size];
struct callbackStruct *tailArray[ip_array_size];
static pthread_mutex_t mtx[ip_array_size];

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    int queueNum, rcv_len, err;
    struct callbackStruct *localBuff, *lastBuff;
    unsigned char *rawData;
    struct pkt_buff *pkBuff;
    struct iphdr *ip;
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t source_ip, dest_ip;

    localBuff = malloc(sizeof(struct callbackStruct));
    lastBuff = NULL;

    localBuff->queue = queue;
    localBuff->nfad = nfad;
    localBuff->next = NULL;

    memcpy(&queueNum, (int *)data, sizeof(int));

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
    uint32_t source_ip, dest_ip;
    struct nfq_q_handle *queue;
    struct nfq_data *nfad;
    struct callbackStruct *tempNode;
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

        for (int i = 0; i < ip_array_size; i++)
        {

            source_ip = callbackStructArray[i]->source_ip;
            dest_ip = callbackStructArray[i]->dest_ip;
            printf("Q: %p NFAD %p\n", callbackStructArray[i]->queue, callbackStructArray[i]->nfad);
            printf("PACKET ID: %u\n", callbackStructArray[i]->packet_id);
            printf("s %u.%u.%u.%u d %u.%u.%u.%u\n", ((unsigned char *)&source_ip)[3], ((unsigned char *)&source_ip)[2], ((unsigned char *)&source_ip)[1], ((unsigned char *)&source_ip)[0], ((unsigned char *)&dest_ip)[3], ((unsigned char *)&dest_ip)[2], ((unsigned char *)&dest_ip)[1], ((unsigned char *)&dest_ip)[0]);
            nfq_set_verdict(queue, callbackStructArray[i]->packet_id, NF_ACCEPT, 0, NULL);

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
                free(tempNode);
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
        printf("pkt received %ld\n", ++packet_count);
        nfq_handle_packet(handler, buf, rcv_len);
    }
    return 0;
}

int main()
{
    struct nfq_q_handle *queue[ip_array_size];
    pthread_t rt, vt;
    int queueNum[ip_array_size];
    struct callbackStruct *tempNode;

    for (int i = 0; i < ip_array_size; i++)
    {
        callbackStructArray[i] = NULL;
        tailArray[i] = NULL;
        mtx[i] = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
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

    while (1)
    {
        continue;
    }

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

    nfq_close(handler);
    return 0;
}