CC = g++
CFLAGS = -Wall -I/opt/cuda/include
LDFLAGS = -Wall -lOpenCL

all: descrack

descrack: descrack.cpp

clean:
	rm -f descrack
