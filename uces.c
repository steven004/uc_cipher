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
#include "aes.h"
#include "uces.h"



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

void UCES_shared_key()

/*
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
*/
