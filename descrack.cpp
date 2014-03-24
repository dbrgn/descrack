/*
 Bitslice DES cracker using OpenCL
 Copyright Daniel Thornburgh 2012
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <CL/opencl.h>
#include <iostream>
#include <cstdio>
#include <cstring>

using namespace std;

#define CHECK(x) if ((err = (x)) != CL_SUCCESS) { throw x; }

void CL_CALLBACK ctxError(const char *errinfo, const void *private_info, size_t cb, void *user_data)
{
    std::cerr << "OpenCL Error: " << errinfo;
}

char *source = NULL;

void readSource(const char *fname, char *dst)
{
    FILE* file = fopen(fname, "r");
    if (!file) {
        std::cerr << "Could not open file " << fname << std::endl;
        abort();
    }

    fseek(file, 0, SEEK_END);
    long len = ftell(file);
    fseek(file, 0, SEEK_SET);

    source = new char[len+1];

    int nRead = fread(source, sizeof(char), len, file);
    source[nRead] = '\0';
}

static void printBin(const char *name, unsigned int x) {
    int i;
    char c[33];
    for (i = 0; i < 32; i++, x >>= 1) {
        c[32-i-1] = (x & 1) ? '1' : '0';
    }
    c[32] = '\0';
    std::cout << name << ":" << c << std::endl;
}

// For bitslicing, the LSB of each slice is index zero, and the first slice
// contains the MSB of the data.

/* Puts data x of size sz into a bitsliced array bsArray at position pos.
 * bsArray assumed to contain zero at that position. */
static void setBitSlice(unsigned int bsArray[], unsigned char x[], size_t sz, char pos)
{
    int i, j, bitnum;
    for (i = 0, bitnum = 0; i < sz; i++) {
        unsigned char mask;
        for (j = 7, mask = 0x80; j >= 0; mask >>= 1, bitnum++, j--) {
            unsigned int bit = (unsigned int)(x[i] & mask) >> j;
            bsArray[bitnum] |= bit << (31 - pos);
        }
    }
}

/* Gets data of size sz from a bitsliced array bsArray at position pos.*/
static void getBitSlice(unsigned int bsArray[], char x[], size_t sz, char pos)
{
    unsigned int mask = 1 << (31 - pos);
    int i;
    for (i = 0; i < sz*8; i++) {
        x[i/8] <<= 1;
        x[i/8] |= (bsArray[i] & mask) >> (31 - pos);
    }
}


/* IP, fully unrolled */
static void ip(unsigned int in[], unsigned int out[])
{
    out[0] = in[57];
    out[1] = in[49];
    out[2] = in[41];
    out[3] = in[33];
    out[4] = in[25];
    out[5] = in[17];
    out[6] = in[9];
    out[7] = in[1];
    out[8] = in[59];
    out[9] = in[51];
    out[10] = in[43];
    out[11] = in[35];
    out[12] = in[27];
    out[13] = in[19];
    out[14] = in[11];
    out[15] = in[3];
    out[16] = in[61];
    out[17] = in[53];
    out[18] = in[45];
    out[19] = in[37];
    out[20] = in[29];
    out[21] = in[21];
    out[22] = in[13];
    out[23] = in[5];
    out[24] = in[63];
    out[25] = in[55];
    out[26] = in[47];
    out[27] = in[39];
    out[28] = in[31];
    out[29] = in[23];
    out[30] = in[15];
    out[31] = in[7];
    out[32] = in[56];
    out[33] = in[48];
    out[34] = in[40];
    out[35] = in[32];
    out[36] = in[24];
    out[37] = in[16];
    out[38] = in[8];
    out[39] = in[0];
    out[40] = in[58];
    out[41] = in[50];
    out[42] = in[42];
    out[43] = in[34];
    out[44] = in[26];
    out[45] = in[18];
    out[46] = in[10];
    out[47] = in[2];
    out[48] = in[60];
    out[49] = in[52];
    out[50] = in[44];
    out[51] = in[36];
    out[52] = in[28];
    out[53] = in[20];
    out[54] = in[12];
    out[55] = in[4];
    out[56] = in[62];
    out[57] = in[54];
    out[58] = in[46];
    out[59] = in[38];
    out[60] = in[30];
    out[61] = in[22];
    out[62] = in[14];
    out[63] = in[6];
}

void doEndSwap(unsigned int tmp[]) {
    // XOR Swap
    // L = L XOR R
    tmp[0] ^= tmp[32];
    tmp[1] ^= tmp[33];
    tmp[2] ^= tmp[34];
    tmp[3] ^= tmp[35];
    tmp[4] ^= tmp[36];
    tmp[5] ^= tmp[37];
    tmp[6] ^= tmp[38];
    tmp[7] ^= tmp[39];
    tmp[8] ^= tmp[40];
    tmp[9] ^= tmp[41];
    tmp[10] ^= tmp[42];
    tmp[11] ^= tmp[43];
    tmp[12] ^= tmp[44];
    tmp[13] ^= tmp[45];
    tmp[14] ^= tmp[46];
    tmp[15] ^= tmp[47];
    tmp[16] ^= tmp[48];
    tmp[17] ^= tmp[49];
    tmp[18] ^= tmp[50];
    tmp[19] ^= tmp[51];
    tmp[20] ^= tmp[52];
    tmp[21] ^= tmp[53];
    tmp[22] ^= tmp[54];
    tmp[23] ^= tmp[55];
    tmp[24] ^= tmp[56];
    tmp[25] ^= tmp[57];
    tmp[26] ^= tmp[58];
    tmp[27] ^= tmp[59];
    tmp[28] ^= tmp[60];
    tmp[29] ^= tmp[61];
    tmp[30] ^= tmp[62];
    tmp[31] ^= tmp[63];

    // R = L XOR R
    tmp[32] ^= tmp[0];
    tmp[33] ^= tmp[1];
    tmp[34] ^= tmp[2];
    tmp[35] ^= tmp[3];
    tmp[36] ^= tmp[4];
    tmp[37] ^= tmp[5];
    tmp[38] ^= tmp[6];
    tmp[39] ^= tmp[7];
    tmp[40] ^= tmp[8];
    tmp[41] ^= tmp[9];
    tmp[42] ^= tmp[10];
    tmp[43] ^= tmp[11];
    tmp[44] ^= tmp[12];
    tmp[45] ^= tmp[13];
    tmp[46] ^= tmp[14];
    tmp[47] ^= tmp[15];
    tmp[48] ^= tmp[16];
    tmp[49] ^= tmp[17];
    tmp[50] ^= tmp[18];
    tmp[51] ^= tmp[19];
    tmp[52] ^= tmp[20];
    tmp[53] ^= tmp[21];
    tmp[54] ^= tmp[22];
    tmp[55] ^= tmp[23];
    tmp[56] ^= tmp[24];
    tmp[57] ^= tmp[25];
    tmp[58] ^= tmp[26];
    tmp[59] ^= tmp[27];
    tmp[60] ^= tmp[28];
    tmp[61] ^= tmp[29];
    tmp[62] ^= tmp[30];
    tmp[63] ^= tmp[31];

    // L = L XOR R
    tmp[0] ^= tmp[32];
    tmp[1] ^= tmp[33];
    tmp[2] ^= tmp[34];
    tmp[3] ^= tmp[35];
    tmp[4] ^= tmp[36];
    tmp[5] ^= tmp[37];
    tmp[6] ^= tmp[38];
    tmp[7] ^= tmp[39];
    tmp[8] ^= tmp[40];
    tmp[9] ^= tmp[41];
    tmp[10] ^= tmp[42];
    tmp[11] ^= tmp[43];
    tmp[12] ^= tmp[44];
    tmp[13] ^= tmp[45];
    tmp[14] ^= tmp[46];
    tmp[15] ^= tmp[47];
    tmp[16] ^= tmp[48];
    tmp[17] ^= tmp[49];
    tmp[18] ^= tmp[50];
    tmp[19] ^= tmp[51];
    tmp[20] ^= tmp[52];
    tmp[21] ^= tmp[53];
    tmp[22] ^= tmp[54];
    tmp[23] ^= tmp[55];
    tmp[24] ^= tmp[56];
    tmp[25] ^= tmp[57];
    tmp[26] ^= tmp[58];
    tmp[27] ^= tmp[59];
    tmp[28] ^= tmp[60];
    tmp[29] ^= tmp[61];
    tmp[30] ^= tmp[62];
    tmp[31] ^= tmp[63];

}

int main(void)
{
    unsigned char pText[] = { 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63 };
    unsigned char cText[] = { 0x4c, 0xc2, 0x90, 0x01, 0x54, 0x8f, 0xcd, 0x95 };

    // Bitslice
    unsigned int bsP[64];
    unsigned int bsC[64];
    memset(bsP, 0, sizeof(bsP));
    memset(bsC, 0, sizeof(bsC));

    for (int i = 0; i < 32; i++) {
        setBitSlice(bsP, pText, 8, i);
        setBitSlice(bsC, cText, 8, i);
    }

    
    
    cl_platform_id platform;
    cl_uint        num_platforms;
    
    cl_device_id device;
    cl_uint num_devices;
    
    cl_ulong lMemSize;
    size_t maxWGSize;
    
    cl_context ctx;
    cl_mem ptBuf;
    cl_mem ctBuf;
    cl_mem resBuf;
    cl_program program;
    cl_kernel kernel;
    cl_command_queue queue;
    
    
    // Permute
    unsigned int permP[64];
    unsigned int permC[64];
    ip(bsP, permP);
    ip(bsC, permC);

    // Do end swap
    doEndSwap(permC);

    // Print ciphertext
    for (int i = 0; i < 64; i++) {
        printBin("Desired", permC[i]);
    }

    readSource("crack.cl", source);

    cl_int err = CL_SUCCESS;

    try {
        // Hardcoded plaintext/ciphertext blocks
        // Get Platform ID
        CHECK(clGetPlatformIDs(1, &platform, &num_platforms));
        std::cout << "Found " << num_platforms << " platforms." << std::endl;

        // Get GPU
        CHECK(clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, &num_devices));
        std::cout << "Found " << num_devices << " GPUs." << std::endl;

        // Get GPU info
        CHECK(clGetDeviceInfo(device, CL_DEVICE_LOCAL_MEM_SIZE, sizeof(lMemSize), &lMemSize, NULL));
        CHECK(clGetDeviceInfo(device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(maxWGSize), &maxWGSize, NULL));
        std::cout << "GPU: Local mem size: " << lMemSize << std::endl;
        std::cout << "GPU: Max workgroup size: " << maxWGSize << std::endl;

        // Create Context
        const cl_context_properties props[] =
            { CL_CONTEXT_PLATFORM, (cl_context_properties)platform, 0 };
        ctx = clCreateContext(props, 1, &device, ctxError, NULL, &err);
        if (err != CL_SUCCESS) {
            throw err;
        }

        // Create Command Queue
        queue = clCreateCommandQueue(ctx, device, CL_QUEUE_PROFILING_ENABLE, &err);
        if (err != CL_SUCCESS) {
            throw err;
        }

        // Create Buffer for plaintext
        ptBuf = clCreateBuffer(ctx, CL_MEM_READ_ONLY, 64*sizeof(unsigned int), NULL, &err);
        if (err != CL_SUCCESS) {
            throw err;
        }

        // Create Buffer for ciphertext
        ctBuf = clCreateBuffer(ctx, CL_MEM_READ_ONLY, 64*sizeof(unsigned int), NULL, &err);
        if (err != CL_SUCCESS) {
            throw err;
        }

        // Create Buffer for result
        resBuf = clCreateBuffer(ctx, CL_MEM_READ_WRITE, 3*sizeof(unsigned int), NULL, &err);
        if (err != CL_SUCCESS) {
            throw err;
        }

        // Create Program
        program = clCreateProgramWithSource(ctx, 1, (const char**)&source, NULL, &err);
        if (err != CL_SUCCESS) {
            throw err;
        }

        // Build Program
        err = clBuildProgram(program, 1, &device, NULL, NULL, NULL);
        if (err == CL_BUILD_PROGRAM_FAILURE) {
            // Print build error
            char log[5120];
            clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, sizeof(log), log, NULL);
            std::cerr << "Build Error:" << std::endl << log;
            throw err;
        }
        if (err != CL_SUCCESS) {
            throw err;
        }

        // Create kernel
        kernel = clCreateKernel(program, "crack", &err);
        if (err != CL_SUCCESS) {
            throw err;
        }

        std::cout << "Kernel created." << std::endl;

        // Set kernel arguments
        CHECK(clSetKernelArg(kernel, 0, sizeof(ptBuf), &ptBuf));
        CHECK(clSetKernelArg(kernel, 1, sizeof(ctBuf), &ctBuf));
        CHECK(clSetKernelArg(kernel, 2, sizeof(ctBuf), &resBuf));

        // Write plaintext to device
        CHECK(clEnqueueWriteBuffer(queue, ptBuf, CL_FALSE, 0, 64*sizeof(unsigned int), permP, 0, NULL, NULL));
        // Write ciphertext to device
        CHECK(clEnqueueWriteBuffer(queue, ctBuf, CL_FALSE, 0, 64*sizeof(unsigned int), permC, 0, NULL, NULL));
        unsigned int zeros[3] = {0,0,0};
        // Write ciphertext to device
        CHECK(clEnqueueWriteBuffer(queue, resBuf, CL_FALSE, 0, 3*sizeof(unsigned int), zeros, 0, NULL, NULL));

        // Enqueue kernel
        cl_event event;
        //size_t localSize[] = { 1, 64 };
        //size_t workSize[] = {1, 1};
        //size_t workSize[] = {0x1, 0x80000000};
        size_t workSize[] = {0x1, 0x10000000};
        //size_t offset[] = { 0xD04B4, 0x5635419D };
        size_t offset[] = { 0xD04B4, 0x50000000 };
        //size_t offset[] = {0, 0};
        CHECK(clEnqueueNDRangeKernel(queue, kernel, 2, offset, workSize, 0, 0, NULL, &event));

        std::cout << "Enqueued." << std::endl;

        // Read results and print
        unsigned int hostbuf[3] = { 0 };
        CHECK(clEnqueueReadBuffer(queue, resBuf, CL_TRUE, 0, sizeof(hostbuf), hostbuf, 0, NULL, NULL));

        for (int i = 0; i < 3; i++) {
            printBin("Obtained", hostbuf[i]);
        }

        // Print info on times
        cl_ulong begin = 0, end = 0;
        CHECK(clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_START, sizeof(begin), &begin, NULL));
        CHECK(clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_END, sizeof(end), &end, NULL));

        // Calculate stats
        double time = (double)(end - begin) / 1000 / 1000 / 1000;
        std::cout << "Run time: " << time << " s" << std::endl;

        double rate = (float)workSize[0] * workSize[1] * 32 / time;
        std::cout << "Rate: " <<  rate / 1000 / 1000 << " Mkeys/s" << std::endl;

        double keyspace = 72057594037927936;
        std::cout << "Time to search keyspace: " << keyspace / rate / 60 / 60 / 24 << " days" << std::endl;

    
    }
    catch (int err) {
        if (err != CL_SUCCESS) {
            std::cerr << "Error: " << err << std::endl;
        }     
    }

    // Do any needed deallocation
    clReleaseMemObject(ptBuf);
    clReleaseMemObject(ctBuf);
    clReleaseMemObject(resBuf);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(ctx);

    return 0;
}
