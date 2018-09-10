### Ciphering lib for ......

Shared key via curve25519
- private key is not kept on client side, to be calculated every time

Symmetric ciphering based on AES128 with some enhancement

See details in file uces.h


### How to build

#make
   
   will generate 2 libraries, libuces.so and libuces.a, libuces.so is dynamic link library, and libuces.a is the static link library.
   
   also, will generate the test program: aes_test, test_curve25519 and uc_test
   
#make clean
   
   clean all build files.
  

