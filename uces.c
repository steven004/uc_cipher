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
#include "aes.h"
#include "uces.h"
#include "sha256.h"

#include <sys/utsname.h>

void get_cpuid (char *id);
int get_mac(char* mac);

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

/* To get the a client's public key, which also depends on the device used by the users
  TO get the client public key, there are a few steps:
  0) to calculate user finger print which is only related to user information (not in this function)
  1) to detect device info and generate device finger print
  2) to generate the corresponding private key
  3) to calculate the corresponding public key
*/

void UCES_client_pubkey(uint8_t* pub_key, const uint8_t* user_fingerprint, void (*device_fp_cb)(uint8_t* dev_fp))
{
  uint8_t device_fp[32];
  uint8_t pri_key[32];
  sha256_context ctx;
  static const uint8_t basepoint[32] = {9};
  uint8_t user_fingerprint_tmp[32];

  memcpy(user_fingerprint_tmp, user_fingerprint, 32);

  if (device_fp_cb)
    device_fp_cb(device_fp);
  else
    UCES_device_fingerprint(device_fp);
  sha256_init(&ctx);
  sha256_hash(&ctx, user_fingerprint_tmp, 32);
  sha256_hash(&ctx, device_fp, 32);
  sha256_done(&ctx, pri_key);

  curve25519_donna(pub_key, pri_key, basepoint);
}

/* To generate the decrypt key for a particular piece of content
  Algorithm: ENHANCED_AES
  All Keys are 32bytes long
*/
void UCES_decrypt_key(uint8_t* uc_dec_key, const uint8_t* shared_key, const uint8_t* uc_enc_key)
{
  memcpy(uc_dec_key, uc_enc_key, 32);
  UCES_encrypt_content(shared_key, uc_dec_key, 32);
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

/* Decrypt a piece of content using uc_dec_key (32bytes)
  To decrypt the content, there are a few steps as below:
  0) get server_pub_key, get user's fingerprint (not in this function)
  1) detect the user's device and calculate the device finger print
  2) calculate the user's private key (related to the device)
  3) calculate the sharedkey between the server and the client/device
  4) decrypt the symmetric key for content
  5) decode the content
*/
void UCES_decrypt_content(const uint8_t* uc_dec_key, uint8_t* buf, uint32_t length,
              const uint8_t* user_fp, const uint8_t* server_pub_key)
{
  struct AES_ctx e_ctx;
  uint8_t uc_enc_key[32];
  uint8_t device_fp[32];
  uint8_t user_fingerprint[32];
  uint8_t pri_key[32];
  sha256_context sha_ctx;
  uint8_t shared_key[32];

  UCES_device_fingerprint(device_fp);
  sha256_init(&sha_ctx);

  sha256_hash(&sha_ctx, user_fingerprint, 32);
  sha256_hash(&sha_ctx, device_fp, 32);
  sha256_done(&sha_ctx, pri_key);

  curve25519_donna(shared_key, pri_key, server_pub_key);
  UCES_decrypt_key(uc_enc_key, shared_key, uc_dec_key);

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
