/* This is only for EAES testing.
  it only work when defined ENHANCED_AES == 1
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"
#if defined(ENHANCED_AES) && (ENHANCED_AES == 1)
#include "uces.h"

static void phex(uint8_t* str);

char short_text[37] = "0123456789abcdefghijklmnopqrstuvwxy";

char ori_text[4096] = " \
How many roads must a man walk down \
Before you can call him a man? \
Yes, and how many seas must a white dove sail \
Before she sleeps in the sand? \
Yes, and how many times must cannonballs fly \
Before they're forever banned? \
\
The answer, my friend, is blowin' in the wind \
The answer is blowin' in the wind \
";


void custom_device_fingerprint(uint8_t* device_fp)
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


  memcpy(device_info.cpu_info, "Intel Core 2 Duo", 16);

  memcpy(device_info.mac_address, "\0x2345fd874587", 6);

  memcpy(device_info.OS_type, "Linux", 16);

  UCES_user_fingerprint(device_fp, (uint8_t *)&device_info, (uint32_t)sizeof(device_context));
}


int main(void)
{
    int i;

    uint8_t * chunk = (uint8_t *)malloc(256 * 1024);

    memset(chunk, 0, 256* 1024);

    for( i = 0; i < 256; i++) {
        memset(chunk + i*1024, 0xa5, 1);
    }


    printf("\n================== Server ===================\n\n");
    //Server: generate random number with seed1 = 0 and seed2 = 0
    uint8_t random_num_server[32], random_num_server2[32], random_num_server3[32];
    UCES_random_32(random_num_server, 0, 0);

    printf("Server Random number #1 is: \n");
    phex(random_num_server);

    //Server: generate random number 2nd time, the seed1 is not zero
    UCES_random_32(random_num_server2, time(NULL), 0);

    printf("Server Random number #2 is: \n");
    phex(random_num_server2);

    //Server: generate random number 3rd time, the seed2 is not zero
    UCES_random_32(random_num_server3, time(NULL), 0);

    printf("Server Random number #3 is: \n");
    phex(random_num_server3);

    //Server: generate random number 4th time, both seed1 and seed2 is not zero
    UCES_random_32(random_num_server3, time(NULL), time(NULL) + 20180912);

    printf("Server Random number #4 is: \n");
    phex(random_num_server3);

    //Server: generate key for content encryption
    uint8_t content_enc_key[32];
    UCES_random_32(content_enc_key, 0, 0);

    printf("Server content encryption key is: \n");
    phex((char *)content_enc_key);

    //Server: encrypt the short content 1st time
    uint8_t encrypt_text1[64] = {0, };
    
    memcpy(encrypt_text1, short_text, sizeof(short_text));
    UCES_encrypt_content(content_enc_key, encrypt_text1, 64);
    printf("Server encrypted text 1st time is:\n");
    
    for (i = 0; i < sizeof(encrypt_text1); ++i)
        printf("%.2x", encrypt_text1[i]);
    printf("\n\n");


    //Server: encrypt the short content 2nd time
    uint8_t encrypt_text2[64] = {0, };
    
    memcpy(encrypt_text2, short_text, sizeof(short_text));
    UCES_encrypt_content(content_enc_key, encrypt_text2, 64);
    printf("Server encrypted text 2nd time is:\n");
    for (i = 0; i < sizeof(encrypt_text2); ++i)
        printf("%.2x", encrypt_text2[i]);
    printf("\n\n");

    //Compare the encrypted content
    if (memcmp(encrypt_text1, encrypt_text2, 64) == 0 )
        printf("encrypted text are same\n\n");
    else
        printf("encrypted text are not same!!!\n\n");


    //Server: encrypt the content
    uint8_t long_text[4096] = {0, };
    memcpy(long_text, ori_text, 4096);
    printf("Server original long text is: \n%s\n", long_text);
    UCES_encrypt_content(content_enc_key, long_text, 1024);


    //Server: encrypt the chunk data
    UCES_encrypt_content(content_enc_key, chunk, 256*1024);


    printf("\n================== Client ===================\n\n");

    //Client generate fingerprint
    uint8_t fingerprint[32] = {0,}, fingerprint2[32] = {0,};
    uint8_t user_info[32] = {"password@username"};
    UCES_user_fingerprint(fingerprint, user_info, 32);

    printf("Client fingerprint is: \n");
    phex(fingerprint);
    

    //Client generate fingerprint 2nd time, the result should same
    UCES_user_fingerprint(fingerprint2, user_info, 32);

    printf("Client fingerprint #2 is: \n");
    phex(fingerprint2);

    //Compare the fingerprint1 and fingerprint2
    if (memcmp(fingerprint, fingerprint2, 32) == 0 )
        printf("fingerprint are same\n\n");
    else
        printf("fingerprint are not same!!!\n\n");


    struct user {
       uint8_t username[16];
       uint8_t pasword[16];

    } user_info2 = {"username", "passowrd"};

    //Client generate fingerprint 3rd time
    uint8_t fingerprint3[32] = {0,}, fingerprint4[32] = {0,};
    
    UCES_user_fingerprint(fingerprint3, (uint8_t *)&user_info2, 32);

    printf("Client fingerprint #3 is: \n");
    phex(fingerprint3);


    //Client generate fingerprint 4th time, the result should same
    UCES_user_fingerprint(fingerprint4, (uint8_t *)&user_info2, 32);

    printf("Client fingerprint #4 is: \n");
    phex(fingerprint4);

    //Compare the fingerprint3 and fingerprint4
    if (memcmp(fingerprint3, fingerprint4, 32) == 0 )
        printf("fingerprint are same\n\n");
    else
        printf("fingerprint are not same!!!\n\n");


    //Client: generate private key
    uint8_t prikey_client[32];
    UCES_client_prikey(prikey_client, fingerprint, NULL);

    printf("Client private key is: \n");
    phex(prikey_client);

    //Client: generate private key 2nd time, the key should same
    uint8_t prikey_client2[32];
    UCES_client_prikey(prikey_client2, fingerprint, NULL);

    printf("Client private key #2 is: \n");
    phex(prikey_client2);

    //Client: generate private key 3rd time with different fingerprint
    uint8_t prikey_client3[32];
    UCES_client_prikey(prikey_client3, fingerprint3, NULL);

    printf("Client private key #3 is: \n");
    phex(prikey_client3);

    //Client: generate private key 4th time, the key should same as #3
    uint8_t prikey_client4[32];
    UCES_client_prikey(prikey_client4, fingerprint3, NULL);

    printf("Client private key #4 is: \n");
    phex(prikey_client4);

    //Client: generate public key
    uint8_t pubkey_client[32] = {0};
    UCES_client_pubkey(pubkey_client, fingerprint, NULL);

    printf("Client public key is: \n");
    phex(pubkey_client);


    //Client: generate public key with callback
    uint8_t pubkey_client1[32] = {0, };

    UCES_client_pubkey(pubkey_client1, fingerprint, custom_device_fingerprint);

    printf("Client public key with customized device fingerprint is: \n");
    phex(pubkey_client1);


    //Server: get the client public key and generate the decrypt key
    uint8_t uc_dec_key[64];
    UCES_gen_decrypt_key(uc_dec_key, random_num_server, content_enc_key, pubkey_client);

    uint8_t uc_dec_key1[64];
    UCES_gen_decrypt_key(uc_dec_key1, random_num_server, content_enc_key, pubkey_client1);

    //Client: get the decrypt key from server, and decrypt the content
    uint8_t client_text[4096] = {0};

    //decrypt the short text
    memcpy(client_text, encrypt_text1, sizeof(encrypt_text1));

    UCES_decrypt_content(uc_dec_key1, client_text, 4096,
              fingerprint, custom_device_fingerprint);

    printf("Client decryped short text with customized device fingerprint is: \n%s\n\n", client_text);

    //Compare the content
    if (strncmp(client_text, short_text, strlen(short_text)) == 0 )
        printf("\n============== Short text decryption test is ok =============\n\n");
    else
        printf("\n================ Test failed ============\n");




    //decrypt the long text
    memset(client_text, 0, 4096);
    memcpy(client_text, long_text, sizeof(long_text));

    UCES_decrypt_content(uc_dec_key, client_text, 4096,
              fingerprint, NULL);

    printf("Client decryped long text is: \n%s\n", client_text);

    //Compare the content
    if (strncmp(client_text, ori_text, strlen(ori_text)) == 0 )
        printf("\n============== Long text decryption test is ok =============\n\n");
    else
        printf("\n================ Test failed ============\n");


    //decrypt the chunk data
    UCES_decrypt_content(uc_dec_key, chunk, 256*1024,
              fingerprint, NULL);

    //check the chunk data
    printf("check with chunk, should be 0xa5 \n");
    for ( i = 0; i < 256; i++) {
         printf("%.2x", chunk[i*1024]);
    }
    printf("\n");


    free(chunk);

    printf("\n================== END  ===================\n\n"); 

    return 0;
}


// prints string as hex
static void phex(uint8_t* str)
{

    uint8_t len = 32;

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n\n\n");
}

#endif  // ENHANCED_AES==1
