CXX      = clang++
CXXFLAGS = -g -std=c++11 -Wall -I/opt/intel/opencl-sdk/include/
LDLIBS   = -lOpenCL

all: descrack opencl_device_test

descrack: descrack.cpp

opencl_device_test: opencl_device_test.cpp

clean:
	rm -f descrack opencl_device_test

.PHONY: clean
