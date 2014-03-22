CC      = g++
#CFLAGS  = -Wall -g -I/opt/cuda/include
CFLAGS  = -Wall -g -I/opt/intel/opencl-sdk/include/
LDFLAGS = -Wall -g -lOpenCL

all: descrack opencl_device_test

descrack: descrack.cpp

opencl_device_test: opencl_device_test.cpp

clean:
	rm -f descrack opencl_device_test

.PHONY: clean
