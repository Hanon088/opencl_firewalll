//
// Created by Tanate on 11/11/2022.
//

// c, cl headers
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <CL/cl.h>
#include <stdbool.h>
#include "src/src.h"
#include <pthread.h>
#include <linux/types.h>

// nfq headers
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>

#define ip_array_size 5
#define rule_array_size 4

long int packet_count = 0;
long int batch_num = 0;
int netf_fd;
char buf[0xffff] __attribute__((aligned));
struct nfq_handle *handler;

/*int ip_array_size = 20;
int rule_array_size = 4;*/

unsigned char string_ip[4];
// uint32_t array_ip_input[ip_array_size];       // input ip array (uint32)
uint32_t rule_ip[rule_array_size];            // input rule_ip (ip uint32)
uint32_t mask[rule_array_size];               // input mask (mask uint32)
bool result[ip_array_size * rule_array_size]; // output array order

// what if we can use pkt_buff instead
struct callbackStruct
{
    struct nfq_q_handle *queue;
    // struct nfgenmsg *nfmsg;
    struct nfq_data *nfad;
    // void *data;
    struct callbackStruct *next;
};

struct callbackStruct *callbackStructArray[ip_array_size];
struct callbackStruct *tailArray[ip_array_size];
static pthread_mutex_t mtx[ip_array_size];
static int packetNumInQ[ip_array_size];

const char *source = "/home/tanate/github/opencl_firewalll/compare.cl";
const char *func = "compare";

// example value
#define printable_ip(addr)           \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    int queueNum, err;
    struct callbackStruct *localBuff, *lastBuff;
    localBuff = malloc(sizeof(struct callbackStruct));
    lastBuff = NULL;

    // localBuff->queue = malloc(sizeof(struct nfq_q_handle *));
    localBuff->nfad = malloc(sizeof(struct nfq_data));

    localBuff->queue = queue;
    // localBuff->nfad = nfad;
    memcpy(localBuff->nfad, nfad, sizeof(struct nfq_data));
    localBuff->next = NULL;

    memcpy(&queueNum, (int *)data, sizeof(int));
    printf("QUEUE NUM %d PACKET NUM %d\n", queueNum, packetNumInQ[queueNum] + 1);

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

int compare_with_mask(uint32_t array_ip_input[], uint32_t rule_ip[], uint32_t mask[], bool result[], int ip_arr_size, int rule_arr_size)
{
    // opencl structures
    cl_device_id deviceId;
    cl_context context;
    cl_program program;
    cl_kernel kernel;
    cl_command_queue queue;
    cl_int err;

    // Data and Buffer
    cl_mem packet_buffer, rule_buffer, mask_buffer, output_buffer;

    // create cl_device
    deviceId = create_device_cl();
    // crate context
    context = clCreateContext(NULL, 1, &deviceId, NULL, NULL, &err);
    print_err(err);

    // build program;
    program = create_program_cl(context, deviceId, source);

    // define 10 workgroup 1 local workgroup
    size_t global_size[] = {rule_arr_size, ip_arr_size};
    size_t local_size[] = {1, 1};
    size_t global_offset[] = {0, 0};

    // create data_buffer for read and write
    // maybe move buffer and queue creation to another function? to optimise data flow
    packet_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ip_arr_size * sizeof(uint32_t), array_ip_input, &err);
    print_err(err);

    rule_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint32_t), rule_ip, &err);
    print_err(err);

    mask_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_arr_size * sizeof(uint32_t), mask, &err);
    print_err(err);

    output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, rule_arr_size * ip_arr_size * sizeof(bool), result, &err);
    print_err(err);

    queue = clCreateCommandQueueWithProperties(context, deviceId, 0, &err);
    print_err(err);

    // crate kernel from source and func
    kernel = clCreateKernel(program, func, &err);
    print_err(err);

    // set kernel function arguments
    err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &packet_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), &rule_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel, 2, sizeof(cl_mem), &mask_buffer);
    print_err(err);
    err |= clSetKernelArg(kernel, 3, sizeof(cl_mem), &output_buffer);
    print_err(err);

    // Enqueue kernel to device
    err = clEnqueueNDRangeKernel(queue, kernel, 2, global_offset, global_size, local_size, 0, NULL, NULL);
    print_err(err);

    // read result buffer in kernel
    err = clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, ip_arr_size * rule_arr_size * sizeof(bool), result, 0, NULL, NULL);
    print_err(err);
    // release resources
    clReleaseKernel(kernel);
    clReleaseMemObject(packet_buffer);
    clReleaseMemObject(rule_buffer);
    clReleaseMemObject(output_buffer);
    clReleaseCommandQueue(queue);
    clReleaseProgram(program);
    clRetainContext(context);
    return 0;
}

void *verdictThread()
{
    int rcv_len, err;
    unsigned char *rawData;
    struct pkt_buff *pkBuff;
    struct iphdr *ip;
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t source_ip, dest_ip;
    struct nfq_q_handle *queue;
    // struct nfq_data *nf_address;
    struct callbackStruct *tempNode;
    uint32_t array_ip_input[ip_array_size]; // input ip array (uint32)

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
        // is it enought to check that a next exists?
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
            struct nfq_data *nf_address = NULL;
            queue = callbackStructArray[i]->queue;
            nf_address = callbackStructArray[i]->nfad;

            printf("VERDICT THREAD - QUEUE NUM %d PACKET NUM %d\n", i, packetNumInQ[i]);

            while (!nf_address)
            {
            get_next_in_q:;
                nf_address = NULL;

                err = pthread_mutex_lock(&mtx[i]);
                if (err != 0)
                {
                    fprintf(stderr, "pthread_mutex_lock fails\n");
                    exit(1);
                }
                if (!callbackStructArray[i])
                {
                    err = pthread_mutex_unlock(&mtx[i]);
                    if (err != 0)
                    {
                        fprintf(stderr, "pthread_mutex_unlock fails\n");
                        exit(1);
                    }
                    goto get_next_in_q;
                }
                if (callbackStructArray[i]->next)
                {
                    tempNode = NULL;
                    /*tempNode = callbackStructArray[i]->next;
                    free(callbackStructArray[i]);
                    callbackStructArray[i] = tempNode;
                    packetNumInQ[i]--;*/

                    tempNode = callbackStructArray[i];
                    callbackStructArray[i] = callbackStructArray[i]->next;
                    tempNode->queue = NULL;
                    // tempNode->nfad = NULL;
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

                printf("VERDICT THREAD - QUEUE NUM %d PACKET NUM %d\n", i, packetNumInQ[i]);

                queue = callbackStructArray[i]->queue;
                nf_address = callbackStructArray[i]->nfad;
            }

            printf("OUT OF NFAD LOOP, Q: %p NFAD IN LOOP: %p NFAD IN BUFF: %p\n", queue, nf_address, callbackStructArray[i]->nfad);

            ph = nfq_get_msg_packet_hdr(nf_address);
            if (!ph)
            {
                printf("ph fails, GOING BACK IN LOOP\n");
                goto get_next_in_q;
                /*fprintf(stderr, "Can't get packet header\n");
                exit(1);*/
            }

            printf("PACKET ID: %u\n", ntohl(ph->packet_id));

            rawData = NULL;
            rcv_len = nfq_get_payload(nf_address, &rawData);
            if (rcv_len < 0)
            {
                printf("get payload fails, GOING BACK IN LOOP\n");
                nfq_set_verdict(queue, ntohl(ph->packet_id), NF_DROP, 0, NULL);
                goto get_next_in_q;
                /*fprintf(stderr, "Can't get raw data\n");
                exit(1);*/
            }
            printf("RCV LEN %d\n", rcv_len);

            // does pkBuff needs to be set to NULL first?
            pkBuff = pktb_alloc(AF_INET, rawData, rcv_len, 0xfff);
            if (!pkBuff)
            {
                printf("pktBuff fails, GOING BACK IN LOOP\n");
                nfq_set_verdict(queue, ntohl(ph->packet_id), NF_DROP, 0, NULL);
                goto get_next_in_q;
                /*fprintf(stderr, "Issue while pktb allocate\n");
                exit(1);*/
            }

            ip = nfq_ip_get_hdr(pkBuff);
            if (!ip)
            {
                printf("ip fails, GOING BACK IN LOOP\n");
                nfq_set_verdict(queue, ntohl(ph->packet_id), NF_DROP, 0, NULL);
                goto get_next_in_q;
                /*
                fprintf(stderr, "Issue while ipv4 header parse\n");
                exit(1);
                */
            }

            source_ip = ntohl(ip->saddr);
            dest_ip = ntohl(ip->daddr);
            printf("s %u.%u.%u.%u d %u.%u.%u.%u\n", ((unsigned char *)&source_ip)[3], ((unsigned char *)&source_ip)[2], ((unsigned char *)&source_ip)[1], ((unsigned char *)&source_ip)[0], ((unsigned char *)&dest_ip)[3], ((unsigned char *)&dest_ip)[2], ((unsigned char *)&dest_ip)[1], ((unsigned char *)&dest_ip)[0]);
            pktb_free(pkBuff);

            // does this help?
            err = pthread_mutex_lock(&mtx[i]);
            if (err != 0)
            {
                fprintf(stderr, "pthread_mutex_lock fails\n");
                exit(1);
            }
            if (callbackStructArray[i]->next)
            {
                tempNode = NULL;
                /*tempNode = callbackStructArray[i]->next;
                free(callbackStructArray[i]->queue);
                free(callbackStructArray[i]->nfad);
                free(callbackStructArray[i]);
                callbackStructArray[i] = tempNode;*/

                tempNode = callbackStructArray[i];
                callbackStructArray[i] = callbackStructArray[i]->next;
                tempNode->queue = NULL;
                // tempNode->nfad = NULL;
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

            nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
            array_ip_input[i] = source_ip;
            // memcpy(array_ip_input[i], &source_ip, 4);
        }

        // check rule_ip ip on cpu
        bool test;
        for (int i = 0; i < rule_array_size; i++)
        {
            printf("%s %d: %u.%u.%u.%u mask : %u.%u.%u.%u\n", "rule_ip", i, printable_ip(rule_ip[i]), printable_ip(mask[i]));
        }
        for (int i = 0; i < ip_array_size; i++)
        {
            for (int j = 0; j < rule_array_size; j++)
            {
                test = rule_ip[j] == (array_ip_input[i] & mask[j]);
                printf("%d", test);
                printf(" | %u.%u.%u.%u ", printable_ip(array_ip_input[i]));
            }
            printf("\n");
        }

        compare_with_mask(array_ip_input, rule_ip, mask, result, ip_array_size, rule_array_size);
        for (int i = 0; i < sizeof(result) / sizeof(bool); i++)
        {
            printf("%d", result[i]);
            if (i % rule_array_size == rule_array_size - 1)
            {
                printf("\n");
            }
        }

        // packet_count %= ip_array_size;
    }
}

void *recvThread()
{
    int rcv_len;

    while (1)
    {
        rcv_len = recv(netf_fd, buf, sizeof(buf), 0);
        // rcv_len = recv(netf_fd, argsrt1.buf, sizeof(argsrt1.buf), MSG_DONTWAIT);
        /* Would multiple buffer do anything?
           Since recv would be using the same netf_fd
        */

        // discarding everything that is smaller than minimum ip packet size
        if (rcv_len < 21)
            continue;
        printf("pkt received %ld\n", ++packet_count);
        /* Is this asynchronous for each queue?
           Does the loop wait for packet handling to be done?
         */
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

    // initialize data copy ip and set rule_ip(uint32_t array)
    for (int i = 0; i < rule_array_size; i++)
    {
        string_ip[3] = (unsigned int)192;
        string_ip[2] = (unsigned int)168 + i;
        string_ip[1] = (unsigned int)0;
        string_ip[0] = (unsigned int)0;
        memcpy(&rule_ip[i], string_ip, 4);
        string_ip[3] = (unsigned int)255;
        string_ip[2] = (unsigned int)255;
        string_ip[1] = (unsigned int)0;
        string_ip[0] = (unsigned int)0;
        memcpy(&mask[i], string_ip, 4);
    }

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