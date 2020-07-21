#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matteo Rizzo");
MODULE_DESCRIPTION("Demo module for kRetroWrite");
MODULE_VERSION("1.0");

static ssize_t demo_write(struct file *f, const char __user *data, size_t size, loff_t *off);

static struct file_operations demo_fops = {
	.write = demo_write,
};

static int major_number;
static struct class *demo_class = NULL;
static struct device *demo_device = NULL;

static ssize_t demo_write(struct file *f, const char __user *data, size_t size, loff_t *off)
{
	char *alloc = kmalloc(16, GFP_KERNEL);

	memset(alloc, 'A', 16);

	copy_from_user(alloc, data, 4);

	if (alloc[0] == '1' && alloc[1] == '3' && alloc[2] == '3' && alloc[3] == '7') {
		printk(KERN_INFO "%02x\n", alloc[16]);
	} else {
		printk(KERN_INFO "%02x\n", alloc[15]);
	}

	kfree(alloc);

	return size;
}

static int __init demo_init(void)
{
	major_number = register_chrdev(0, "demo", &demo_fops);
	if (major_number < 0) {
		printk(KERN_ALERT "failed to register a major number");
		return major_number;
	}

	demo_class = class_create(THIS_MODULE, "demo");
	if (IS_ERR(demo_class)) {
		unregister_chrdev(major_number, "demo");
		printk(KERN_ALERT "failed to register a class");
		return PTR_ERR(demo_class);
	}

	demo_device = device_create(demo_class, NULL, MKDEV(major_number, 0), NULL, "demo");
	if (IS_ERR(demo_device)) {
		class_unregister(demo_class);
		unregister_chrdev(major_number, "demo");
		return PTR_ERR(demo_device);
	}

	printk(KERN_INFO "Demo module loaded\n");
	return 0;
}

static void __exit demo_exit(void)
{
	device_destroy(demo_class, MKDEV(major_number, 0));
	class_unregister(demo_class);
	unregister_chrdev(major_number, "demo");
	printk(KERN_INFO "Demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
