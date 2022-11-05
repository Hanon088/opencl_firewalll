/*
Multiple queue
One recv loop
One verdict thread
Store nfad as array of linked list of struct, one linked list for each queue
Send verdict as soon as all linked list has a next node

Need full packets from iptables to be tested
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
// #include <string.h>
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

long int packet_count = 0;

// what if we can use pkt_buff instead
struct callbackStruct
{
    // pointer to queue which packet is stored
    struct nfq_q_handle *queue;

    // pointer to packet data in queue, not sure where it is stored
    struct nfq_data *nfad;
    struct callbackStruct *next;
};

struct callbackStruct *callbackStructArray[2];

static int netfilterCallback0(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    struct callbackStruct *localBuff, *lastBuff;
    localBuff = malloc(sizeof(struct callbackStruct));
    lastBuff = NULL;

    localBuff->queue = queue;
    localBuff->nfad = nfad;
    localBuff->next = NULL;

    if (!callbackStructArray[0])
    {
        callbackStructArray[0] = localBuff;
    }
    else
    {
        lastBuff = callbackStructArray[0];
        while (lastBuff->next)
        {
            lastBuff = lastBuff->next;
        }
        lastBuff->next = localBuff;
    }

    return 0;
}

static int netfilterCallback1(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    struct callbackStruct *localBuff, *lastBuff;
    localBuff = malloc(sizeof(struct callbackStruct));
    lastBuff = NULL;

    localBuff->queue = queue;
    localBuff->nfad = nfad;
    localBuff->next = NULL;

    if (!callbackStructArray[1])
    {
        callbackStructArray[1] = localBuff;
    }
    else
    {
        lastBuff = callbackStructArray[1];
        while (lastBuff->next)
        {
            lastBuff = lastBuff->next;
        }
        lastBuff->next = localBuff;
    }

    return 0;
}

void *verdictThread()
{
    int rcv_len;
    unsigned char *rawData;
    struct pkt_buff *pkBuff;
    struct iphdr *ip;
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t source_ip, dest_ip;
    struct nfq_q_handle *queue;
    struct nfq_data *nfad;
    struct callbackStruct *tempNode;
    while (1)
    {
        if (!(callbackStructArray[0]) || !(callbackStructArray[1]))
        {
            continue;
        }
        break;
    }

    while (1)
    {

        if (!(callbackStructArray[0]->next) || !(callbackStructArray[1]->next))
        {
            continue;
        }
        for (int i = 0; i < 2; i++)
        {
            queue = callbackStructArray[i]->queue;

            // where does nfad point to? A copy of user space buffer? kernel buffer?
            nfad = callbackStructArray[i]->nfad;

            // packet header added by netfilter
            ph = nfq_get_msg_packet_hdr(nfad);
            if (!ph)
            {
                fprintf(stderr, "Can't get packet header\n");
                exit(1);
            }

            rawData = NULL;
            // get packet data from nfad
            rcv_len = nfq_get_payload(nfad, &rawData);
            if (rcv_len < 0)
            {
                fprintf(stderr, "Can't get raw data\n");
                exit(1);
            }

            // allocate user space buffer???
            pkBuff = pktb_alloc(AF_INET, rawData, rcv_len, 0x1000);
            if (!pkBuff)
            {
                fprintf(stderr, "Issue while pktb allocate\n");
                exit(1);
            }

            ip = nfq_ip_get_hdr(pkBuff);
            if (!ip)
            {
                fprintf(stderr, "Issue while ipv4 header parse\n");
                exit(1);
            }

            source_ip = ntohl(ip->saddr);
            dest_ip = ntohl(ip->daddr);
            printf("s %u.%u.%u.%u d %u.%u.%u.%u\n", ((unsigned char *)&source_ip)[3], ((unsigned char *)&source_ip)[2], ((unsigned char *)&source_ip)[1], ((unsigned char *)&source_ip)[0], ((unsigned char *)&dest_ip)[3], ((unsigned char *)&dest_ip)[2], ((unsigned char *)&dest_ip)[1], ((unsigned char *)&dest_ip)[0]);
            pktb_free(pkBuff);
            nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);

            tempNode = NULL;
            tempNode = callbackStructArray[i]->next;
            free(callbackStructArray[i]);
            callbackStructArray[i] = tempNode;
        }
    }
}

int main()
{
    int fd;
    int rcv_len;
    char buf[4096] __attribute__((aligned));
    struct nfq_handle *handler;
    struct nfq_q_handle *queue0, *queue1;
    pthread_t vt;

    callbackStructArray[0] = NULL;
    callbackStructArray[1] = NULL;

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

    queue0 = nfq_create_queue(handler, 0, netfilterCallback0, NULL);
    queue1 = nfq_create_queue(handler, 1, netfilterCallback1, NULL);
    /* The kernel may send this in parallel?
       How would the handle receive this? Sequentially?
       Each queue seems to be processed asyncrhonously, try using multiple callback functions
     */
    if (!queue0 && !queue1)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(queue0, NFQNL_COPY_PACKET, 0xffff) < 0 || nfq_set_mode(queue1, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(handler);
    pthread_create(&vt, NULL, verdictThread, NULL);

    while (1)
    {
        // Let's assume that buf is overwritten in each call
        rcv_len = recv(fd, buf, sizeof(buf), 0);
        printf("pkt received %ld\n", ++packet_count);
        nfq_handle_packet(handler, buf, rcv_len);
    }

    nfq_destroy_queue(queue0);
    nfq_destroy_queue(queue1);
    nfq_close(handler);
    return 0;
}