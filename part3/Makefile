obj-m += communicate.o
all:
	sudo make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install
clean:
	sudo make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
