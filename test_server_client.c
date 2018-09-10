/* This is only for EAES testing.
  it only work when defined ENHANCED_AES == 1
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
#define CBC 1
#define CTR 1
#define ECB 1

#include "aes.h"
#if defined(ENHANCED_AES) && (ENHANCED_AES == 1)
#include "uces.h"

static void phex(uint8_t* str);

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

int main(void)
{

    printf("\n================== Server ===================\n\n");
    //Server: generate random number
    uint8_t random_num_server[32], random_num_server2[32], random_num_server3[32];
    UCES_random_32(random_num_server, 0, 0);

    printf("Server Random number #1 is: \n");
    phex(random_num_server);

    //Server: generate random number 2nd time, the number should not same
    UCES_random_32(random_num_server2, 0, 0);

    printf("Server Random number #2 is: \n");
    phex(random_num_server2);

    //Server: generate random number 3rd time, the number should not same
    UCES_random_32(random_num_server3, 0, 0);

    printf("Server Random number #3 is: \n");
    phex(random_num_server3);

    //Server: generate key for content encryption
    uint8_t content_enc_key[32];
    UCES_random_32(content_enc_key, 0, 0);

    printf("Server content encryption key is: \n");
    phex((char *)content_enc_key);

    //Server: encrypte the content
    uint8_t plain_text[4096] = {0};
    memcpy(plain_text, ori_text, 4096);
    printf("Server original plain text is: \n%s\n", plain_text);
    UCES_encrypt_content(content_enc_key, plain_text, 1024);


    printf("\n================== Client ===================\n\n");

    //Client generate fingerprint
    uint8_t fingerprint[32] = {0}, fingerprint2[32] = {0};
    uint8_t user_info[32] = {"password@username"};
    UCES_user_fingerprint(fingerprint, user_info, 32);

    printf("Client fingerprint is: \n");
    phex(fingerprint);
    

    //Client generate fingerprint 2nd time, the result should same
    UCES_user_fingerprint(fingerprint2, user_info, 32);

    printf("Client fingerprint #2 is: \n");
    phex(fingerprint2);

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

    //Client: generate public key
    uint8_t pubkey_client[32] = {0};
    UCES_client_pubkey(pubkey_client, fingerprint, NULL);

    printf("Client public key is: \n");
    phex(pubkey_client);


    //Server: get the client public key and generate the decrypt key
    uint8_t uc_dec_key[64];
    UCES_gen_decrypt_key(uc_dec_key, random_num_server, content_enc_key, pubkey_client);

    //Client: get the decrypt key from server, and decrypt the content
    uint8_t client_text[4096] = {0};
    memcpy(client_text, plain_text, 4096);

    UCES_decrypt_content(uc_dec_key, client_text, 4096,
              fingerprint, NULL);

    printf("Client decryped text is: \n%s\n", client_text);

    //Compare the content
    if (strncmp(client_text, ori_text, strlen(ori_text)) == 0 )
        printf("\n================ Test is ok =============\n");
    else
        printf("\n================ Test failed ============\n");


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
