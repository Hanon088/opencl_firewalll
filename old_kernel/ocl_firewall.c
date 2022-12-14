#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
//#include "device_controller.h"

static struct nf_hook_ops *check_rules_ops = NULL;

static unsigned int check_rules(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    u32 source_ip;
    u32 dest_ip;
    struct sk_buff *sb = NULL;
    struct iphdr *iph;
    sb = skb;
    iph = ip_hdr(sb);
    unsigned int verdict;
    /*ntohl convert network byteorder into host byteorder
    network byteorder = big endian
    host byteorder = most likely little endian?
    gpu byteorder = little endian
    */
    source_ip = ntohl(iph->saddr);
    dest_ip = ntohl(iph->daddr);
    printk(KERN_INFO "OCL FIREWALL s %u.%u.%u.%u d %u.%u.%u.%u\n", ((unsigned char*)&source_ip)[3], ((unsigned char*)&source_ip)[2], ((unsigned char*)&source_ip)[1], ((unsigned char*)&source_ip)[0], ((unsigned char*)&dest_ip)[3], ((unsigned char*)&dest_ip)[2], ((unsigned char*)&dest_ip)[1], ((unsigned char*)&dest_ip)[0]);
    //verdict = check_rules_in_device();
    verdict = NF_ACCEPT;
    return verdict;
}

static int __init ocl_firewall_init(void)
{
    check_rules_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (check_rules_ops != NULL)
    {
        check_rules_ops->hook = (nf_hookfn *)check_rules;
        check_rules_ops->hooknum = NF_INET_PRE_ROUTING;
        check_rules_ops->pf = NFPROTO_IPV4;
        check_rules_ops->priority = NF_IP_PRI_FIRST;

        nf_register_net_hook(&init_net, check_rules_ops);
    }
    printk(KERN_INFO "OCL FIREWALL LOADED\n");
    return 0;
}

static void __exit ocl_firewall_exit(void)
{
    if (check_rules_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, check_rules_ops);
        kfree(check_rules_ops);
    }
    printk(KERN_INFO "OCL FIREWALL REMOVED\n");
}

module_init(ocl_firewall_init);
module_exit(ocl_firewall_exit);