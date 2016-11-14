/* 
 * libc.c	Kernel C library wrapper
 *
 * Copyright (C) 2016 Seongmyun Cho <highsky@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

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
	return kcalloc(nmemb, size, GFP_ATOMIC);
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
