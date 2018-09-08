/* Define functions to be invoked by Server or Users
  The library will be provided as shared object and this header file
*/

#ifndef _UCES_H_
#define _UCES_H_

#include <stdint.h>


/*
// In this version, only CBC mode is supported
#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: both IV and KEY are required for encryption and decryption
//        no IV should ever be reused with the same key
void UCES_encrypt_buffer(const uint8_t* key, const uint8_t* iv, uint8_t* buf, uint32_t length);
void UCES_decrypt_buffer(const uint8_t* key, const uint8_t* iv, uint8_t* buf, uint32_t length);
#endif // #if defined(CBC) && (CBC == 1)
*/

// To get the shared key from The server's private key and a client's public Key
// In this version, the size of every key parameter is 32 bytes
// This functions is only invoked by a service provider on the server side
int UCES_shared_key(uint8_t* shared_key, const uint8_t* server_pri_key, const uint8_t* client_pub_key);

/*
// To get the shared key by a client, using server's public key and user/device info
// In this version, the size of every key parameter is 32 bytes
// This functions is only invoked by an end user on the client side
int UCES_shared_key_client(uint_t* shared_key, const uint8_t* user_fp,
                            const uint8_t* device_fp, const uint8_t* server_pub_key);
*/


// To get the deciphering key for a particular piece of contents
// all the parameters are 32bytes long.
//    shared_key: the key shared by the server and client who needs to read the contents
//    uc_enc_key: the key to encrypt the particular contents
//    uc_dec_key: the key to be used only by the particular client to decrypt the contents,
//                anybody else who get this key could not decrypt the encoded contents
void UCES_decrypt_key(uint8_t* uc_dec_key, const uint8_t* shared_key, const uint8_t* uc_enc_key);

// To encrypt the content in buf using uc_enc_key (32 bytes long)
// The length must be multiple of block size (16 bytes)
//    otherwise, buf will be over flowed
void UCES_encrypt_content(const uint8_t* uc_enc_key, uint8_t* buf, uint32_t length);

// To decrypt the content in buf using uc_dec_key (32 bytes long)
// The length must be multiple of block size (16 bytes)
//    otherwise, buf will be over flowed
void UCES_decrypt_content(const uint8_t* uc_dec_key, uint8_t* buf, uint32_t length,
              const uint8_t* user_fp, const uint8_t* server_pub_key);

// To generate the public key for a client from the user finger print and device finger print
// user_fingerprint and device_fingerprint are both 32 bytes
// pub_key: 32 bytes
void UCES_client_pubkey(uint8_t* pub_key, const uint8_t* user_fingerprint, void (*device_fp_cb)(uint8_t* dev_fp));

// To generate the finger print of the user's device. (internal function, not need to invoke by users)
// The finger print is a 32-byte number
// This function is an example and replacible. You could write your own device finger print function
// Please notice there is no input for this functioin, but to detect device info by the func itself
void UCES_device_fingerprint(uint8_t* dev_fp);

// To generate the finger print of a user
// This can be custermized by a service provider, who could use any user specified information
//    such as user name, password, ID, ...
// The finger print is a 32-byte number
void UCES_user_fingerprint(uint8_t* user_fp, const uint8_t* user_info, uint32_t length);

// To generate 32-byte public Key from a private key (32bytes)
// In general, any 32-byte number could be a private key, but, the server should use a
//  strong cryptographic way to produce a private key, which is not include in this lib.
void UCES_pubkey_gen(uint8_t* pub_key, uint8_t* pri_key);


#endif //_UCES_H_
