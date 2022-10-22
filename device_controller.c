#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <unistd.h>
#include <stdio.h>
#include <CL/cl.h>
#include <netinet/in.h>
// #include <libnetfilter_queue/libnetfilter_queue.h>
#define CL_TARGET_OPENCL_VERSION 120

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	char *data;
    FILE *stdout;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);
		//processPacketData (data, ret);
	}
	fputc('\n', stdout);

	return id;
}



unsigned int check_rules_in_device(void)
{
    // create kernel here? Or can we just queue it
    return NF_ACCEPT;
}

int load_device_code()
{
    // load the device code into global var
    return 0;
}

int load_rule_file()
{
    // load the rules from a file into global var
    return 0;
}

int main()
{
    int err;
    err = load_rule_file();
    // then alloc rule into device
    uint32_t ip;
    // printf("%d\n", ip);
    err = load_device_code();
    // create program here
    // cl_uint *ip_uint32 = (cl_uint*)malloc(sizeof(cl_uint));
    // ip_uint32 = 11000000,10101000,00000001;
    // printf("%u.%u.%u.%u", (unsigned char*)&ip_uint32[0], ((unsigned char*)&ip_uint32)[1], (unsigned char*)&ip_uint32[2],(unsigned char*)&ip_uint32[3]);
    // printf("%u", (unsigned char)CL_DEVICE_ADDRESS_BITS);
    return 0;
}