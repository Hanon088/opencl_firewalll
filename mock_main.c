#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include "device_controller.h"

static struct nf_hook_ops *check_rules_ops = NULL;

static unsigned int check_rules(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    printk(KERN_INFO "OCL FIREWALL RUNNING\n");
    return NF_ACCEPT;
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
    printk(KERN_INFO "OCL FIREWALL REMOVED\n");
}

module_init(ocl_firewall_init);
module_exit(ocl_firewall_exit);