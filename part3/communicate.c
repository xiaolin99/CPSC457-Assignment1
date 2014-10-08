/*
CPSC 457 Fall2014 HW1 - Part3
by Xiao Lin
Reference:
- LKM example (tutorial handout)
- http://linuxgazette.net/133/saha.html
*/
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/crc32.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>


// define device
static struct miscdevice communicate_dev;

// define read operations
static ssize_t communicate_read(struct file *file, char *buf, size_t count, loff_t *ppos) {
  struct task_struct *task;
  unsigned int crc32_checksum;
  int len;
  char *buffer;
  int offset;
  len = sizeof(long)* + sizeof(int)*2 + sizeof(pid_t) + sizeof(uid_t) + sizeof(pgd_t);
  buffer = (char*)vmalloc(len);
  if (!buffer) {
    printk("Failed to allocate memory for read() of communicate module\n");
    return -ENOMEM;
  }
  // macro to go through all currest task (from sched.h)
  for_each_process(task) {
    // clear the buffer, then concatenate all required fields into buffer
    memset(buffer, 0, sizeof(buffer));
    offset = 0;
    memcpy(buffer, (char*)&(task->state), sizeof(long));
    offset = offset + sizeof(long);
    memcpy(buffer+offset, (char*)&(task->ptrace), sizeof(int)); 
    offset = offset + sizeof(int);
    memcpy(buffer+offset, (char*)&(task->personality), sizeof(int));
    offset = offset + sizeof(int);
    memcpy(buffer+offset, (char*)&(task->pid), sizeof(pid_t));
    offset = offset + sizeof(pid_t);
    if (task->real_cred) memcpy(buffer+offset, (char*)&(task->real_cred->uid), sizeof(uid_t));
    offset = offset + sizeof(uid_t);
    memcpy(buffer+offset, (char*)&(task->thread.ip), sizeof(long));
    offset = offset + sizeof(long);
    if (task->mm)  memcpy(buffer+offset, (char*)&(task->mm->pgd), sizeof(pgd_t));
   
    // calculate checksum (assuming little-endian) and print
    crc32_checksum = crc32_le(0, buffer, len);
    printk("%s(%d) - CRC32: 0x%08x\n", task->comm, task->pid, crc32_checksum);
  }
  vfree(buffer);
  return 0;
}

// define write operation - simply return "Operation not permmited" error code
static ssize_t communicate_write(struct file *file, const char *buf, size_t count, loff_t *ppos) {
  printk("Communicate module does not support write operations\n");
  return -EPERM;
}

static const struct file_operations communicate_fops = {.read = communicate_read, .write=communicate_write,};

// define module load operation
static int communicate_start(void) {
  int ret;
  printk("Loading communicate module ... \n");
  communicate_dev.minor = MISC_DYNAMIC_MINOR;
  communicate_dev.name = "communicate";
  communicate_dev.fops = &communicate_fops;
  ret = misc_register(&communicate_dev);
  if(ret) printk("Uable to register ... \n");
  return ret;
}

// define module unload operation
static void communicate_end(void) {
  int ret;
  printk("Goodbye\n");
  ret = misc_deregister(&communicate_dev);
  printk("Unregistering\n");
  if(ret) printk("unable to deregister ...\n");
}

module_init(communicate_start);
module_exit(communicate_end);
