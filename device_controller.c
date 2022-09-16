#include <stdio.h>
#include <stdlib.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <CL/cl.h>

unsigned int check_rules_in_device()
{
    // create kernel here? Or can we just queue it
    return NF_ACCEPT
}

int load_device_code()
{
    // load the device code into global var
    return 0
}

int load_rule_file()
{
    // load the rules from a file into global var
    return 0
}

int init_device()
{
    int err;
    err = load_rule_file();
    // then alloc rule into device

    err = load_device_code();
    // create program here
    return 0
}