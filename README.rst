DES Cracker
==========

This is an OpenCL DES cracker, originally by `Daniel Thornburgh
<http://www.reddit.com/r/crypto/comments/162ufx/research_project_opencl_bitslice_des_bruteforce/>`__
and improved as a research project at the University of Applied Sciences HSR
Rapperswil.

How to build
------------

You may need to adjust the OpenCL include path in the Makefile.

Default compiler is clang. If you prefer GCC, adjust the Makefile accordingly.

To build::

    make

Then run::

    ./descrack
