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

long int packet_count = 0;
int netf_fd;
int rcv_len;
char buf[4096] __attribute__((aligned));
struct nfq_handle *handler;

int ip_array_size = 20;
int rule_array_size = 4;
unsigned char string_ip[4];
uint32_t array_ip_input[ip_array_size];       // input ip array (uint32)
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

struct callbackStruct *callbackStructArray[2];

const char *source = "C:\\Users\\User\\opencl_firewalll\\compare.cl";
const char *func = "compare";

// example value
#define printable_ip(addr)           \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

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
        while (lastBuff->next != NULL)
        {
            lastBuff = lastBuff->next;
        }
        lastBuff->next = localBuff;
    }

    return 0;
}

int compare_with_mask(uint32_t array_ip_input[], uint32_t rule_ip[], uint32_t mask[], bool result[], int ip_array_size, int rule_array_size)
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
    size_t global_size[] = {rule_array_size, ip_array_size};
    size_t local_size[] = {1, 1};
    size_t global_offset[] = {0, 0};

    // create data_buffer for read and write
    // maybe move buffer and queue creation to another function? to optimise data flow
    packet_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ip_array_size * sizeof(uint32_t), array_ip_input, &err);
    print_err(err);

    rule_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_array_size * sizeof(uint32_t), rule_ip, &err);
    print_err(err);

    mask_buffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, rule_array_size * sizeof(uint32_t), mask, &err);
    print_err(err);

    output_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, rule_array_size * ip_array_size * sizeof(bool), result, &err);
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
    err = clEnqueueReadBuffer(queue, output_buffer, CL_TRUE, 0, ip_array_size * rule_array_size * sizeof(bool), result, 0, NULL, NULL);
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
        if (!(callbackStructArray[0]))
        {
            continue;
        }

        if (!(callbackStructArray[0]->next))
        {
            continue;
        }

        if (packet_count < ip_array_size)
        {
            continue;
        }

        tempNode = callbackStructArray[0];
        for (int i = 0; i < ip_array_size; i++)
        {
            printf("At node %i\n", i);

            /*queue = callbackStructArray[0]->queue;
            nfad = callbackStructArray[0]->nfad;*/
            queue = tempNode->queue;
            nfad = tempNode->nfad;

            printf("At node %i p2\n", i);

            if (!nfad || nfad == NULL)
            {
                fprintf(stderr, "What the nfad\n");
                exit(1);
            }

            ph = nfq_get_msg_packet_hdr(nfad);
            printf("At node %i p3\n", i);
            if (!ph)
            {
                fprintf(stderr, "Can't get packet header\n");
                exit(1);
            }

            rawData = NULL;
            rcv_len = nfq_get_payload(nfad, &rawData);
            printf("At node %i p4\n", i);
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
            pktb_free(pkBuff);
            nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);

            tempNode = callbackStructArray[0]->next;
            free(callbackStructArray[0]);
            callbackStructArray[0] = tempNode;

            // memcpy(&array_ip_input[i], &source_ip, 4);
            array_ip_input[i] = source_ip;
        }

        // check rule_ip ip on cpu
        bool test;
        for (int i = 0; i < rule_array_size; i++)
        {
            printf("%s %d: %u.%u.%u.%u mask : %u.%u.%u.%u\n", "rule_ip", i, printable_ip(rule_ip[i]), printable_ip(mask[i]));
            ;
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

        packet_count %= ip_array_size;
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
        if (rcv_len < 0)
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
    struct nfq_q_handle *queue0, *queue1;
    pthread_t vt, rt;

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

    callbackStructArray[0] = NULL;

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

    /* The kernel may send this in parallel?
       How would the handle receive this? Sequentially?
       Each queue seems to be processed asyncrhonously, try using multiple callback functions
     */
    if (!queue0)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(queue0, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    netf_fd = nfq_fd(handler);
    // pthread_create(&vt, NULL, verdictThread, NULL);
    pthread_create(&rt, NULL, recvThread, NULL);

    while (1)
    {
        continue;
    }

    nfq_destroy_queue(queue0);
    nfq_close(handler);

    return 0;
}