/*
 *  linux/fs/proc/kmsg.c
 *
 *  Copyright (C) 1992  by Linus Torvalds
 *
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/syslog.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <linux/sched.h>
#include "internal.h"
extern wait_queue_head_t log_wait;

static int kmsg_open(struct inode * inode, struct file * file)
{
	return do_syslog(SYSLOG_ACTION_OPEN, NULL, 0, SYSLOG_FROM_PROC);
}

static int kmsg_release(struct inode * inode, struct file * file)
{
	(void) do_syslog(SYSLOG_ACTION_CLOSE, NULL, 0, SYSLOG_FROM_PROC);
	return 0;
}

static ssize_t kmsg_read(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	if ((file->f_flags & O_NONBLOCK) &&
	    !do_syslog(SYSLOG_ACTION_SIZE_UNREAD, NULL, 0, SYSLOG_FROM_PROC))
		return -EAGAIN;
	return do_syslog(SYSLOG_ACTION_READ, buf, count, SYSLOG_FROM_PROC);
}

static unsigned int kmsg_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &log_wait, wait);
	if (do_syslog(SYSLOG_ACTION_SIZE_UNREAD, NULL, 0, SYSLOG_FROM_PROC))
		return POLLIN | POLLRDNORM;
	return 0;
}


static const struct file_operations proc_kmsg_operations = {
	.read		= kmsg_read,
	.poll		= kmsg_poll,
	.open		= kmsg_open,
	.release	= kmsg_release,
	.llseek		= generic_file_llseek,
};

#ifdef  CONFIG_SCHED_CASIO_POLICY
#define CASIO_MAX_CURSOR_LINES_EVENTS   1

static int casio_open(struct inode *inode, struct file *file)
{
        return 0;
}
static ssize_t casio_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
        char buffer[CASIO_MSG_SIZE];
        unsigned long len=0,k,i;
	
        struct casio_event_log *log=NULL;
        buffer[0]='\0';
        log=get_casio_event_log();
        if(log){
                if(log->cursor < log->lines){
                        k=(log->lines > (log->cursor + CASIO_MAX_CURSOR_LINES_EVENTS))?(log->cursor + CASIO_MAX_CURSOR_LINES_EVENTS):(log->lines);
                        for(i=log->cursor; i<k;i++){
                                len = snprintf(buffer, count, "%s%d,%llu,%s\n",
                                        buffer,
                                        log->casio_event[i].action,
                                        log->casio_event[i].timestamp,
                                        log->casio_event[i].msg);    
                        }
                        log->cursor=k;
                }
                if(len) 
                        copy_to_user(buf,buffer,len);
             
        }
        return (ssize_t)len;
}
static int casio_release(struct inode *inode, struct file *file)
{
        return 0;
}
static const struct file_operations proc_casio_operations = {
        .open           = casio_open,
        .read           = casio_read,
        .release        = casio_release,
};
#endif

static int __init proc_kmsg_init(void)
{

#ifdef  CONFIG_SCHED_CASIO_POLICY
        {
                struct proc_dir_entry *casio_entry;
                casio_entry = proc_create("casio_event", 0666, NULL, &proc_casio_operations);
                if (casio_entry){
                        casio_entry->proc_fops = &proc_casio_operations;
                        casio_entry->data=NULL;
                }
        }
#endif

	proc_create("kmsg", S_IRUSR, NULL, &proc_kmsg_operations);
	return 0;
}
fs_initcall(proc_kmsg_init);
