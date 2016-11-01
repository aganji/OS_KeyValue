//////////////////////////////////////////////////////////////////////
//                             North Carolina State University
//
//
//
//                             Copyright 2016
//
////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
////////////////////////////////////////////////////////////////////////
//
//   Author:  Hung-Wei Tseng
//
//   Description:
//     Skeleton of KeyValue Pseudo Device
//
////////////////////////////////////////////////////////////////////////

#include "keyvalue.h"

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/uaccess.h>

#include <linux/spinlock.h>

unsigned transaction_id=0;
rwlock_t rw_lock;

struct node{
    uint64_t key;
    uint64_t size;
    char*   data;
    struct node* next;
};

struct node *head=NULL;

static void free_callback(void *data)
{
}

static long keyvalue_get(struct keyvalue_get __user *ukv)
{
    struct keyvalue_get *kv;
    struct node *temp_node=NULL;
    uint64_t i=0;
    char *data_get_kptr = NULL;
    int status = 0;
    kv = (struct keyvalue_get*)kmalloc(sizeof(struct keyvalue_get),GFP_KERNEL);
    kv->size = (uint64_t*)kmalloc(sizeof(uint64_t),GFP_KERNEL);
    copy_from_user(&(kv->key),&(ukv->key),sizeof(uint64_t));
    //kv.key = ukv->key;
    printk(KERN_ALERT "KEY VALUE GET: %llu %llu %llu %llu %llu %llu\n",kv->key,kv->size,kv->data,ukv->key,ukv->size,ukv->data);
    read_lock(&rw_lock);

    if (head == NULL){
        return -1;
    }
    else
    {
        temp_node = head;
        
        while(temp_node->key != kv->key && temp_node->next != NULL)
        {
            temp_node = temp_node->next;
        }

        if (temp_node->key == kv->key)
        {
            *(kv->size) = (temp_node->size);
            kv->data = (char *)kmalloc(sizeof(char)*(temp_node->size+1),GFP_KERNEL);
            data_get_kptr = (char *)kv->data;
           
            for(i=0;i<temp_node->size;i++)
            {    
                data_get_kptr[i] = (temp_node->data)[i];
            }
            data_get_kptr[i]='\0';
            status = 1;
        }

    }
    copy_to_user(ukv->size,kv->size,sizeof(uint64_t));
    copy_to_user(ukv->data,kv->data,sizeof(char)*(temp_node->size + 1));
    kfree(kv->size);
    kfree(kv->data);
    read_unlock(&rw_lock);

    write_lock(&rw_lock);
    transaction_id++;
    write_unlock(&rw_lock);

    if (status == 1)
        return transaction_id;
    else
        return -1;
}

static long keyvalue_set(struct keyvalue_set __user *ukv)
{
    struct keyvalue_set kv;
    struct node *node_ptr=NULL;
    struct node *temp_node=NULL;
    struct node *prev_node=NULL;
    char *data_set_kptr = NULL;
    uint64_t i=0;
    int status=0;

    copy_from_user(&kv,ukv,sizeof(struct keyvalue_set));    
    
    printk(KERN_ALERT "KEY VALUE SET 1: %llu %llu %s\n",kv.key,kv.size,(char *)kv.data);

    if (data_set_kptr)
        kfree(data_set_kptr);
        
    if (node_ptr)
        kfree(node_ptr);
            

    data_set_kptr = (char *)kmalloc((sizeof(char)*(kv.size+1)),GFP_KERNEL);
    node_ptr = (struct node *)kmalloc(sizeof(struct node),GFP_KERNEL);
    
    memset(data_set_kptr,0,(sizeof(char)*kv.size)+1);
    
    for(i=0;i<kv.size;i++)
    {
        data_set_kptr[i] = ((char *)(kv.data))[i];
    }
    data_set_kptr[i]='\0';
    
    node_ptr->key = kv.key;
    node_ptr->size = kv.size;
    node_ptr->data = (char *)data_set_kptr;
    node_ptr->next = NULL;
    
    write_lock(&rw_lock);
    if (head == NULL)
        head = node_ptr;
    else
    {
        temp_node = head;
        
        while((temp_node->next != NULL) && (temp_node->key != kv.key))
        {
            prev_node = temp_node;
            temp_node = temp_node->next;    
        }
        
        if (temp_node->key == kv.key && temp_node == head)
        {
            node_ptr->next = head->next;
            head = node_ptr;
            kfree(temp_node);
            status = 1;
        }
        else if (temp_node->key == kv.key)
        {
            prev_node->next = node_ptr;
            node_ptr->next = temp_node->next;
            kfree(temp_node);
            status = 1;

        }
        else if (temp_node->next == NULL)
        {    
            temp_node->next = node_ptr;
            status = 1;
        }
    
    }
    transaction_id++;
    write_unlock(&rw_lock);
    
    if (status == 1)
        return transaction_id;
    else
        return -1;
}

static long keyvalue_delete(struct keyvalue_delete __user *ukv)
{
    struct keyvalue_delete kv;
    int status = 0;
    struct node *temp_node=NULL;
    struct node *prev_node=NULL;

    copy_from_user(&(kv.key),&(ukv->key),sizeof(uint64_t));

    if (head == NULL)
        return status;

    temp_node = head;
    write_lock(&rw_lock);
    while(temp_node != NULL)
    {
        if (temp_node->key == kv.key && temp_node == head)
        {
            head = NULL;
            kfree(temp_node);
            status = 1;
        }
        else if(temp_node->key == kv.key)
        {
            prev_node->next = temp_node->next;
            kfree(temp_node);
            status=1;
        }
        else
        {
            prev_node = temp_node;
            temp_node = temp_node->next;
        }
    }


    
    transaction_id++;
    write_unlock(&rw_lock);

    if (status == 1)
        return transaction_id;
    else
        return -1;
}

//Added by Hung-Wei
     
unsigned int keyvalue_poll(struct file *filp, struct poll_table_struct *wait)
{
    unsigned int mask = 0;
    printk("keyvalue_poll called. Process queued\n");
    return mask;
}

static long keyvalue_ioctl(struct file *filp, unsigned int cmd,
                                unsigned long arg)
{
    switch (cmd) {
    case KEYVALUE_IOCTL_GET:
        return keyvalue_get((void __user *) arg);
    case KEYVALUE_IOCTL_SET:
        return keyvalue_set((void __user *) arg);
    case KEYVALUE_IOCTL_DELETE:
        return keyvalue_delete((void __user *) arg);
    default:
        return -ENOTTY;
    }
}

static int keyvalue_mmap(struct file *filp, struct vm_area_struct *vma)
{
    return 0;
}

static const struct file_operations keyvalue_fops = {
    .owner                = THIS_MODULE,
    .unlocked_ioctl       = keyvalue_ioctl,
    .mmap                 = keyvalue_mmap,
//    .poll       = keyvalue_poll,
};

static struct miscdevice keyvalue_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "keyvalue",
    .fops = &keyvalue_fops,
};

static int __init keyvalue_init(void)
{
    int ret;
    printk(KERN_ALERT "IN KEYVALUE MODULE\n");
    if ((ret = misc_register(&keyvalue_dev)))
        printk(KERN_ERR "Unable to register \"keyvalue\" misc device\n");
    rwlock_init(&rw_lock);
    return ret;
}

static void __exit keyvalue_exit(void)
{
    misc_deregister(&keyvalue_dev);
}

MODULE_AUTHOR("Hung-Wei Tseng <htseng3@ncsu.edu>");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
module_init(keyvalue_init);
module_exit(keyvalue_exit);