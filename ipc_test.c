// kernel libraries
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

// ipv4 libraries
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

// shared memory management
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h> /* copy_from_user, copy_to_user */
#include <linux/slab.h>

static struct nf_hook_ops *check_rules_ops = NULL;
static const char *filename = "OCL_FIREWALL_BUFFER";
unsigned int FILE_COUNT = 0;
_Atomic unsigned int ROUND_ROBIN = 0;

enum
{
	BUFFER_SIZE = 4
};

struct mmap_info
{
	char *data;
};

// may break if multiple open are called
struct mmap_info *global_info;

static unsigned int check_rules(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (!skb)
		return NF_ACCEPT;

	u32 source_ip;
	u32 dest_ip;
	struct sk_buff *sb = NULL;
	struct iphdr *iph;
	u32 ip_set_flag, verdict_set_flag;
	u32 verdict, verdict_a;
	char *local_data;
	sb = skb;
	iph = ip_hdr(sb);
	local_data = global_info->data;
	source_ip = ntohl(iph->saddr);
	dest_ip = ntohl(iph->daddr);
	// printk(KERN_INFO "OCL FIREWALL s %u.%u.%u.%u d %u.%u.%u.%u \n", ((unsigned char *)&source_ip)[3], ((unsigned char *)&source_ip)[2], ((unsigned char *)&source_ip)[1], ((unsigned char *)&source_ip)[0], ((unsigned char *)&dest_ip)[3], ((unsigned char *)&dest_ip)[2], ((unsigned char *)&dest_ip)[1], ((unsigned char *)&dest_ip)[0]);
	verdict = NF_ACCEPT;

	if (FILE_COUNT)
	{
		/*
		BYTE 0 - 3 ip_set_flag
		BYTE 4 - 7 source_ip
		BYTE 8 - 11 dest_ip
		BYTE 12 - 15 verdict_set_flag
		BYTE 16 - 19 verdict
		*/

		// set flags to 0
		ip_set_flag = 0;
		verdict_set_flag = 0;
		memcpy(local_data, &ip_set_flag, 4);
		memcpy(local_data + 12, &verdict_set_flag, 4);

		memcpy(local_data + 4, &source_ip, 4);
		memcpy(local_data + 8, &dest_ip, 4);

		// set ip_set_flag to 1, to tell user module data is there
		ip_set_flag = 1;
		memcpy(local_data, &ip_set_flag, 4);
		ip_set_flag = 0;

		// insert delay here somehow
		// usleep_range(10000, 20000);
		/*if(memcmp(global_info->data + 12, &verdict_set_flag, 4) == 0)
			usleep_range(10000, 20000);*/

		// wait_event(wq, memcmp(global_info->data + 12, &verdict_set_flag, 4) != 0);

		/*wait_thread = kthread_create(wait_function, &verdict_set_flag, "OCLFWAIT");
		if (wait_thread) {
				wake_up_process(wait_thread);
		} else
				pr_info("OCL FIREWALL Wait Thread creation failed\n");

		wake_up_all(&wq);*/
		// immediately change ip_set_flag to 0 to stop user module

		/*while(memcmp(local_data + 12, &verdict_set_flag, 4) == 0){
			usleep_range(100, 200);
		}*/
		memcpy(local_data, &ip_set_flag, 4);

		// read verdict
		memcpy(&verdict_a, local_data + 16, 4);
		printk(KERN_INFO "OCL FIREWALL s %u.%u.%u.%u d %u.%u.%u.%u v %i\n", ((unsigned char *)&source_ip)[3], ((unsigned char *)&source_ip)[2], ((unsigned char *)&source_ip)[1], ((unsigned char *)&source_ip)[0], ((unsigned char *)&dest_ip)[3], ((unsigned char *)&dest_ip)[2], ((unsigned char *)&dest_ip)[1], ((unsigned char *)&dest_ip)[0], verdict_a);
	}

	return (unsigned int *)verdict;
}

/* After unmap. */
static void vm_close(struct vm_area_struct *vma)
{
	pr_info("OCL FIREWALL MMAP vm_close\n");
}

/* First page access. */
static vm_fault_t vm_fault(struct vm_fault *vmf)
{
	struct page *page;
	struct mmap_info *info;

	pr_info("OCL FIREWALL MMAP vm_fault\n");
	info = (struct mmap_info *)vmf->vma->vm_private_data;
	if (info->data)
	{
		page = virt_to_page(info->data);
		get_page(page);
		vmf->page = page;
	}
	return 0;
}

/* Aftr mmap. TODO vs mmap, when can this happen at a different time than mmap? */
static void vm_open(struct vm_area_struct *vma)
{
	pr_info("OCL FIREWALL MMAP vm_open\n");
}

static struct vm_operations_struct vm_ops =
	{
		.close = vm_close,
		.fault = vm_fault,
		.open = vm_open,
};

static int mmap(struct file *filp, struct vm_area_struct *vma)
{
	pr_info("OCL FIREWALL MMAP mmap\n");
	vma->vm_ops = &vm_ops;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = filp->private_data;
	vm_open(vma);
	return 0;
}

static int open(struct inode *inode, struct file *filp)
{
	struct mmap_info *info;

	pr_info("OCL FIREWALL MMAP open\n");
	info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
	pr_info("OCL FIREWALL MMAP virt_to_phys = 0x%llx\n", (unsigned long long)virt_to_phys((void *)info));
	info->data = (char *)get_zeroed_page(GFP_KERNEL);
	filp->private_data = info;
	global_info = info;

	// change this to shared one process only somehow
	FILE_COUNT++;
	return 0;
}

static ssize_t read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
	struct mmap_info *info;
	int ret;

	pr_info("OCL FIREWALL MMAP read\n");
	info = filp->private_data;
	ret = min(len, (size_t)BUFFER_SIZE);
	if (copy_to_user(buf, info->data, ret))
	{
		ret = -EFAULT;
	}
	return ret;
}

static ssize_t write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
	struct mmap_info *info;

	pr_info("OCL FIREWALL MMAP write\n");
	info = filp->private_data;
	if (copy_from_user(info->data, buf, min(len, (size_t)BUFFER_SIZE)))
	{
		return -EFAULT;
	}
	else
	{
		return len;
	}
}

static int release(struct inode *inode, struct file *filp)
{
	struct mmap_info *info;

	pr_info("OCL FIREWALL MMAP release\n");
	info = filp->private_data;
	free_page((unsigned long)info->data);
	kfree(info);
	filp->private_data = NULL;
	FILE_COUNT--;
	return 0;
}

static const struct file_operations fops = {
	.mmap = mmap,
	.open = open,
	.release = release,
	.read = read,
	.write = write,
};

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
	proc_create(filename, 0, NULL, &fops);
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
	remove_proc_entry(filename, NULL);
	printk(KERN_INFO "OCL FIREWALL REMOVED\n");
}

module_init(ocl_firewall_init);
module_exit(ocl_firewall_exit);