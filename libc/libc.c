/*
 *  * main.c − The kernel libc module.
 *   */
#include <linux/types.h>
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/slab.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Seongmyun Cho <highsky@gmail.com>");
MODULE_DESCRIPTION("C library");

void *malloc(size_t size)
{
	return kmalloc(size, GFP_ATOMIC);
}

EXPORT_SYMBOL(malloc);

void *realloc(void *ptr, size_t size)
{
	return krealloc(ptr, size, GFP_ATOMIC);
}

EXPORT_SYMBOL(realloc);

void *calloc(size_t nmemb, size_t size)
{
	return kzalloc(nmemb * size, GFP_ATOMIC);
}

EXPORT_SYMBOL(calloc);

void free(void *ptr)
{
	kfree(ptr);
}

EXPORT_SYMBOL(free);

static int __init libc_init(void)
{
	pr_debug("libc init\n");
	return 0;
}

static void __exit libc_exit(void)
{
	pr_debug("libc exit\n");
}

module_init(libc_init);
module_exit(libc_exit);
