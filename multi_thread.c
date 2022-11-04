/*
One queue
Multiple recv thread
One verdict thread
Store nfad as array of struct
Wait for array to be full before sending verdict
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

#define cbSize 6

volatile long int packet_count = 0;

struct nfq_handle *handler;
int fd;
char bufrt0[4096] __attribute__((aligned));
char bufrt1[4096] __attribute__((aligned));
char bufrt2[4096] __attribute__((aligned));

struct callbackStruct
{
    struct nfq_q_handle *queue;
    //struct nfgenmsg *nfmsg;
    struct nfq_data *nfad;
    //void *data;
};

struct callbackStruct callbackArray[cbSize];
volatile int callbackCount = 0;

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    int localCount = callbackCount++;
    callbackArray[localCount].queue = queue;
    //callbackArray[localCount].nfmsg = nfmsg;
    callbackArray[localCount].nfad = nfad;
    //callbackArray[localCount].data = data;
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
    //struct nfgenmsg *nfmsg;
    struct nfq_data *nfad;
    //void *data;
    while (1)
    {
        if (callbackCount < cbSize)
            continue;
        for (int i = 0; i < cbSize; i++)
        {
            queue = callbackArray[i].queue;
            //nfmsg = callbackArray[i].nfmsg;
            nfad = callbackArray[i].nfad;
            //data = callbackArray[i].data;

            ph = nfq_get_msg_packet_hdr(nfad);
            if (!ph)
            {
                fprintf(stderr, "Can't get packet header\n");
                exit(1);
            }

            rawData = NULL;
            rcv_len = nfq_get_payload(nfad, &rawData);
            if (rcv_len < 0)
            {
                fprintf(stderr, "Can't get raw data\n");
                exit(1);
            }

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
            callbackArray[i].queue = NULL;
            //callbackArray[i].nfmsg = NULL;
            callbackArray[i].nfad = NULL;
            //callbackArray[i].data = NULL;
        }
        callbackCount = 0;
    }
}

void *recvThread0()
{
    int rcv_len;

    while (1)
    {
        if (callbackCount == cbSize)
            continue;
        // printf("THREAD %p, %p \n", args -> buf, &(args->buf));
        rcv_len = recv(fd, bufrt0, sizeof(bufrt0), 0);
        // rcv_len = recv(fd, argsrt1.buf, sizeof(argsrt1.buf), MSG_DONTWAIT);
        /* Would multiple buffer do anything?
           Since recv would be using the same fd
        */
        printf("%d\n", rcv_len);
        if (rcv_len < 0)
            continue;
        printf("pkt received %ld\n", ++packet_count);
        /* Is this asynchronous for each queue?
           Does the loop wait for packet handling to be done?
         */
        nfq_handle_packet(handler, bufrt0, rcv_len);
    }
    return 0;
}

void *recvThread1()
{
    int rcv_len;

    while (1)
    {
        if (callbackCount == cbSize)
            continue;
        // printf("THREAD %p, %p \n", args -> buf, &(args->buf));
        rcv_len = recv(fd, bufrt1, sizeof(bufrt1), 0);
        // rcv_len = recv(fd, argsrt1.buf, sizeof(argsrt1.buf), MSG_DONTWAIT);
        /* Would multiple buffer do anything?
           Since recv would be using the same fd
        */
        printf("%d\n", rcv_len);
        if (rcv_len < 0)
            continue;
        printf("pkt received %ld\n", ++packet_count);
        /* Is this asynchronous for each queue?
           Does the loop wait for packet handling to be done?
         */
        nfq_handle_packet(handler, bufrt1, rcv_len);
    }
    return 0;
}

int main()
{
    int rcv_len;
    struct nfq_q_handle *queue;
    pthread_t rt0, rt1, rt2;
    pthread_t vt0, vt1, vt2;

    // may need multiple handlers
    handler = nfq_open();

    if (!handler)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    /*
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
    }*/

    queue = nfq_create_queue(handler, 0, netfilterCallback, NULL);
    if (!queue)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(handler);

    pthread_create(&rt0, NULL, recvThread0, NULL);
    //pthread_create(&rt1, NULL, recvThread1, NULL);
    pthread_create(&vt0, NULL, verdictThread, NULL);
    //  pthread_create(&t3, NULL, recvThread, (void* )&argst3);

    while (1)
    {
        // printf("MAIN %p, %p \n", &bufrt1, argsrt1.buf);
        /*printf("%p, %p |", &bufrt2, argsrt2.buf);
        printf("%p, %p \n", &buft3, argst3.buf);*/
        continue;
    }

    nfq_destroy_queue(queue);
    nfq_close(handler);
    return 0;
}