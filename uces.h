/* Define functions to be invoked by Server or Users
  The library will be provided as shared object and this header file
*/

#ifndef _UCES_H_
#define _UCES_H_

#include <stdint.h>

// Random function: to generate a 32-byte random number
// The random number could be used as a key or a seed for Keys
// This function is a reference, users can use other random function too.
// Suggest seed1 and seed2 are from client and server respectivey for safe
void UCES_random_32(uint8_t* rand_num, uint32_t seed1, uint32_t seed2);

// To encrypt the content in buf using uc_enc_key (32 bytes long)
// The length must be multiple of block size (16 bytes)
//    otherwise, buf will be over flowed
void UCES_encrypt_content(const uint8_t* uc_enc_key, uint8_t* buf, uint32_t length);

// To generate the decrypt key for a particular piece of content, and a particular piece of content
//  Input:
//    random_num: a 32-byte number, a seed to generate the key
//    uc_enc_key: 32-byte encrypting key for the particular piece of content
//    pubkey_client: the particular client's public key
//  Output: uc_dec_key: 64 bytes, the key for the particular client to decrypt the particular content
void UCES_gen_decrypt_key(uint8_t* uc_dec_key, const uint8_t* random_num,
                        const uint8_t* uc_enc_key, const uint8_t* pubkey_client)


// To generate the finger print of a user
// This can be custermized by a service provider, who could use any user specified information
//    such as user name, password, ID, ...
// The finger print is a 32-byte number
void UCES_user_fingerprint(uint8_t* user_fp, const uint8_t* user_info, uint32_t length);

// To generate the finger print of the user's device. (internal function, not need to invoke by users)
// The finger print is a 32-byte number
// This function is an example and replacible. You could write your own device finger print function
// Please notice there is no input for this functioin, but to detect device info by the func itself
void UCES_device_fingerprint(uint8_t* dev_fp);

// To generate the public key for a client from the user finger print and device finger print
// user_fingerprint and device_fingerprint are both 32 bytes
// pub_key: 32 bytes
void UCES_client_pubkey(uint8_t* pub_key, const uint8_t* user_fingerprint, void (*device_fp_cb)(uint8_t* dev_fp));

/ To decrypt the content in buf using uc_dec_key (32 bytes long)
// The length must be multiple of block size (16 bytes)
//    otherwise, buf will be over flowed
//void UCES_decrypt_content(const uint8_t* uc_dec_key, uint8_t* buf, uint32_t length,
//              const uint8_t* user_fp, const uint8_t* server_pub_key);
void UCES_decrypt_content(const uint8_t* uc_dec_key, uint8_t* buf, uint32_t length,
              const uint8_t* user_fp, void (*device_fp)(uint8_t* dev_fp));

#endif //_UCES_H_
