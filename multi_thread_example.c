/*psuedo code mixed in*/

PacketPool *ppool;

/* Definition of callback function */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    /* Simply copy packet date and send them to a packet pool */
    return push_packet_to_pool(ppool, nfa);
}

int main()
{
    /* Set callback function */
    qh = nfq_create_queue(h, 0, &cb, NULL);
    /* create reading thread */
    pthread_create(read_thread_id, NULL, read_thread, qh);
    /* create verdict thread */
    pthread_create(write_thread_id, NULL, verdict_thread, qh);
    /* … */
}

static void *read_thread(void *fd)
{
    for (;;)
    {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
        {
            nfq_handle_packet(h, buf, rv); /* send packet to callback */
            continue;
        }
    }
}

static void *verdict_thread(void *fd)
{
    for (;;)
    {
        Packet p = fetch_packet_from_pool(ppool);
        u_int32_t id = treat_pkt(nfa, &verdict);   /* Treat packet */
        nfq_set_verdict(qh, id, verdict, 0, NULL); /* Verdict packet */
    }
}
