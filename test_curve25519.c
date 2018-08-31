/*
Usage
The usage is exactly the same as djb's code (as described at http://cr.yp.to/ecdh.html) except that the function is called curve25519_donna.

To generate a private key, generate 32 random bytes and:

mysecret[0] &= 248; mysecret[31] &= 127; mysecret[31] |= 64;

To generate the public key, just do

static const uint8_t basepoint[32] = {9}; curve25519_donna(mypublic, mysecret, basepoint);

To generate a shared key do:

uint8_t shared_key[32]; curve25519_donna(shared_key, mysecret, theirpublic);

And hash the shared_key with a cryptographic hash function before using.

See more at: http://cr.yp.to/ecdh.html
*/

#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>

#ifdef _MSC_VER
#define inline __inline
#endif

typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

int curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint);
int curve25519_pri_key_gen(u8 *private);


int main(void)
{
  static const uint8_t basepoint[32] = {9};
  uint8_t shared_key[32];

}

/* private is a 32byte number */
int curve25519_pri_key_gen(u8 *private)
{
  srand(time(NULL));
  unsigned char i;
  for (i = 0; i < 16; ++i) {
    *(p + i) = rand() & 0xff;
  }
  private[0] &= 248;
  private[31] &= 127;
  private[31] |= 64;
}

static void phex(uint8_t* str)
{
    unsigned char i;
    for (i = 0; i < 32; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

void test_shared_secret()
{
  printf("test_shared_secret:\n");
  u8 prikey_alice[32], prikey_bob[32];
  u8 pubkey_alice[32], pubkey_bob[32];
  u8 sharedkey_alice[32], sharedkey_bob[3];

  curve25519_pri_key_gen(prikey_alice);
  printf("prikey_alice:");
  phex(prikey_alice);

  curve25519_pri_key_gen(prikey_bob);
  printf("prikey_bob:  ");
  phex(prikey_bob);

  static const uint8_t basepoint[32] = {9};
  curve25519_donna(pubkey_alice, prikey_alice, basepoint);
  printf("pubkey_alice:");
  phex(pubkey_alice);

  curve25519_donna(pubkey_bob, prikey_bob, basepoint);
  printf("pubkey_bob:");
  phex(pubkey_bob);

  // Get shared key:
  curve25519_donna(sharedkey_alice, prikey_alice, pubkey_bob);
  printf("sharedkey_alice:");
  phex(sharedkey_alice);

  curve25519_donna(sharedkey_bob, prikey_bob, pubkey_alice);
  printf("sharedkey_bob:");
  phex(sharedkey_bob);
}
