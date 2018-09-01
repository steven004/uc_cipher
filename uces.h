/* Define functions to be invoked by Server or Users
  The library will be provided as shared object and this header file
*/

#ifndef _UCES_H_
#define _UCES_H_

#include <stdint.h>

// In the first version, also for safety reason, only CBC mode is supported
#ifndef CBC
  #define CBC 1
#endif

// particularly for Ulord content cryptography
#ifndef ENHANCED_AES
  #define ENHANCED_AES 1
#endif

// 128bit key as default
#define AES128 1

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: both IV and KEY are required for encryption and decryption
//        no IV should ever be reused with the same key
void UCES_encrypt_buffer(const uint8_t* key, const uint8_t* iv, uint8_t* buf, uint32_t length);
void UCES_decrypt_buffer(const uint8_t* key, const uint8_t* iv, uint8_t* buf, uint32_t length);
#endif // #if defined(CBC) && (CBC == 1)


#endif //_UCES_H_
