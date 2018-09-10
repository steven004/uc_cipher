/*
This implementation is for Ulord content encryption and decryption
The algorithm is based on AES128-CBC with some enhancement

NOTE:   In this encryption/decryption, 128bit key and 128bit iv are required
        String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <stdint.h>
#include <string.h> // CBC mode, for memset
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "aes.h"
#include "uces.h"
#include "sha256.h"

#include <sys/utsname.h>

void get_cpuid (char *id);
int get_mac(char* mac);

static void phex(uint8_t* str)
{
    unsigned char i;
    for (i = 0; i < 32; ++i)
        printf("%.2x", str[i]);
    printf("\n\n");
}

/* The implementation also depends on curve25519-donna.c */
int curve25519_donna(uint8_t *shared_key, const uint8_t *my_pri_key, const uint8_t *his_pub_key);

/* Generate shared key based on my private key and the opposite public key
   All the keys are 32bytes
*/
inline
int UCES_shared_key(uint8_t* shared_key, const uint8_t* server_pri_key, const uint8_t* client_pub_key)
{
  return curve25519_donna(shared_key, server_pri_key, client_pub_key);
}

/*
void UCES_random_32(uint8_t* rand_num, uint32_t seed1, uint32_t seed2)
{
  int      fd;
  uint8_t  tmp[32];

  if ((seed1 == 0) || (seed2 == 0)) {
    seed1 = time(NULL);

    fd = open("/dev/urandom", O_RDWR);

    read(fd, tmp, 32);
    memcpy(rand_num, tmp, 32);

  }
  else {
    srand(seed1 + seed2);
    *rand_num = rand();
  }
}
*/

// Random function: to generate a 32-byte random number
// The random number could be used as a key or a seed for Keys
void UCES_random_32(uint8_t* rand_num, uint32_t seed1, uint32_t seed2)
{
    sha256_context ctx;
    timeval t1, t2;

    sha256_init(&ctx);
    gettimeofday(&t1, NULL);
    if (seed1 == 0) seed1 = 0x8325ab07
    sha256_hash(&ctx, (uint8_t *)&seed1, 4);
    sha256_hash(&ctx, (uint8_t *)&t1, sizeof(timeval))
    if (seed2 == 0)
    {
      gettimeofday(&t2, NULL)
      seed2 = t2.tv_usec - t1.tv_usec
    }
    sha256_hash(&ctx, (uint8_t *)&seed2, 4)
    sha256_done(&ctx, rand_num)
}



/* Generate user fingerprint from user_info */
void UCES_user_fingerprint(uint8_t* user_fp, const uint8_t* user_info, uint32_t length)
{
  sha256_context ctx;
  const char* pre_text = "UC ciphering version 1.0";

  sha256_init(&ctx);
  sha256_hash(&ctx, (uint8_t *)pre_text, (uint32_t)strlen(pre_text));
  sha256_hash(&ctx, (uint8_t *)user_info, length);
  sha256_done(&ctx, user_fp);
}

/* Generate device fingerprint via detection */
void UCES_device_fingerprint(uint8_t* device_fp)
{
  // TODO: add more code based on different operation system.
  //   Or,
  // make it a replacible functions, to let users custermize it

  typedef struct {
      uint8_t cpu_info[16];
      uint8_t mac_address[6];
      uint8_t OS_type[16];
  } device_context;



  device_context device_info;
  memset(&device_info, 0, sizeof(device_context));


  //memcpy(device_info.cpu_info, "Intel Core 2 Duo", 16);
  get_cpuid((char *)device_info.cpu_info);

  //memcpy(device_info.mac_address, "\0x2345fd874587", 6);
  get_mac((char *)device_info.mac_address);

  struct utsname  u;
  if (uname(&u) != -1) {
      memcpy(device_info.OS_type, u.release, 16);
  }

  UCES_user_fingerprint(device_fp, (uint8_t *)&device_info, (uint32_t)sizeof(device_context));
}

void UCES_client_prikey(uint8_t* pri_key, const uint8_t* user_fingerprint, void (*device_fp_cb)(uint8_t* dev_fp))
/* To get the a client's public key, which also depends on the device used by the users
  TO get the client public key, there are a few steps:
  0) to calculate user finger print which is only related to user information (not in this function)
  1) to detect device info and generate device finger print
  2) to generate the corresponding private key
  3) to calculate the corresponding public key
*/
{
  uint8_t device_fp[32] = {0};
  sha256_context ctx;
  uint8_t user_fingerprint_tmp[32] = {0};


  memcpy(user_fingerprint_tmp, user_fingerprint, 32);

  if (device_fp_cb)
    device_fp_cb(device_fp);
  else
    UCES_device_fingerprint(device_fp);
  sha256_init(&ctx);
  sha256_hash(&ctx, user_fingerprint_tmp, 32);
  sha256_hash(&ctx, device_fp, 32);
  sha256_done(&ctx, pri_key);


  //curve25519_donna(pub_key, pri_key, basepoint);
}


/* To get the a client's public key, which also depends on the device used by the users
  TO get the client public key, there are a few steps:
  0) to calculate user finger print which is only related to user information (not in this function)
  1) to detect device info and generate device finger print
  2) to generate the corresponding private key
  3) to calculate the corresponding public key
*/
void UCES_client_pubkey(uint8_t* pub_key, const uint8_t* user_fingerprint, void (*device_fp_cb)(uint8_t* dev_fp))
{
  uint8_t pri_key[32] = {0};
  static const uint8_t basepoint[32] = {9};

  UCES_client_prikey(pri_key, user_fingerprint, *device_fp_cb);


  curve25519_donna(pub_key, pri_key, basepoint);
}


// To generate the decrypt key for a particular piece of content, and a particular piece of content
//  Input:
//    random_num: a 32-byte number, a seed to generate the key
//    uc_enc_key: 32-byte encrypting key for the particular piece of content
//    pubkey_client: the particular client's public key
//  Output: uc_dec_key: 64 bytes, the key for the particular client to decrypt the particular content
//
void UCES_gen_decrypt_key(uint8_t* uc_dec_key, const uint8_t* random_num,
                        const uint8_t* uc_enc_key, const uint8_t* pubkey_client)
{
  uint8_t pubkey_server[32];
  uint8_t sharedkey_server[32];

  static const uint8_t basepoint[32] = {9};
  curve25519_donna(pubkey_server, random_num, basepoint);
  printf("Server public key is: \n");
  phex(pubkey_server);


  // Get shared key:
  curve25519_donna(sharedkey_server, random_num, pubkey_client);
  printf("Server shared key is: \n");
  phex(sharedkey_server);

  memcpy(uc_dec_key, pubkey_server, 32);

  int i;
  for(i=0; i<32; i++){
    sharedkey_server[i] ^= uc_enc_key[i];
  }
  memcpy(uc_dec_key + 32, sharedkey_server, 32);

  //curve25519_donna(sharedkey_client, random_num, pubkey_server);
  //printf("shrdkey_client:\t");
  //phex(sharedkey_client);


}


/* Encrypt a piece of content using the uc_enc_key (32bytes: 256bits)
   Algorithm: ENHANCED_AES
   There are two parts in the uc_enc_key: 1) symmetric key: 128bits, 2) iv: 128bits
   the length must be multiple of 16
*/
void UCES_encrypt_content(const uint8_t* uc_enc_key, uint8_t* buf, uint32_t length)
{
  struct AES_ctx ctx;

  AES_init_ctx_iv(&ctx, uc_enc_key, uc_enc_key+16);
  AES_CBC_encrypt_buffer(&ctx, buf, length);
}



void UCES_decrypt_content(const uint8_t* uc_dec_key, uint8_t* buf, uint32_t length,
              const uint8_t* user_fp, void (*device_fp_cb)(uint8_t* dev_fp))
{
  struct AES_ctx e_ctx;

  uint8_t prikey_client[32];
  uint8_t pubkey_server[32];

  UCES_client_prikey(prikey_client, user_fp, *device_fp_cb);

  printf("Client private key is: \n");
  phex(prikey_client);

  //curve25519_donna(pub_key, pri_key, basepoint);
  uint8_t sharedkey_client[32];

  memcpy(pubkey_server, uc_dec_key, 32);
  curve25519_donna(sharedkey_client, prikey_client, pubkey_server);
  printf("Client shared key is: \n");
  phex(sharedkey_client);

  uint8_t uc_enc_key[32];
  memcpy(uc_enc_key, uc_dec_key + 32, 32);
  int i;
  for(i=0; i<32; i++){
     uc_enc_key[i] ^= sharedkey_client[i];
  }

  printf("Content encryption key:\n");
  phex(uc_enc_key);


  AES_init_ctx_iv(&e_ctx, uc_enc_key, uc_enc_key+16);
  AES_CBC_decrypt_buffer(&e_ctx, buf, length);


}

/*  To generate public key (32bytes) from a private key (32bytes)
*/
void UCES_pubkey_gen(uint8_t* pub_key, uint8_t* pri_key)
{
  static const uint8_t basepoint[32] = {9};
  curve25519_donna(pub_key, pri_key, basepoint);
}


void UCES_encrypt_buffer(const uint8_t* key, const uint8_t* iv, uint8_t* buf, uint32_t length)
{
  struct AES_ctx ctx;

  AES_init_ctx_iv(&ctx, key, iv);
  AES_CBC_encrypt_buffer(&ctx, buf, length);
}

void UCES_decrypt_buffer(const uint8_t* key, const uint8_t* iv, uint8_t* buf, uint32_t length)
{
  struct AES_ctx ctx;

  AES_init_ctx_iv(&ctx, key, iv);
  AES_CBC_decrypt_buffer(&ctx, buf, length);
}
