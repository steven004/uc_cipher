from ctypes import *

UC_CIPHER_LIB_PATH = "/home/steven004/uc_cipher/libuces.so"

def print_key(key, length=32):
    for i in xrange(length):
        print("%2x"%ord(key.raw[i])),
    print("\n")

uc_cipher = cdll.LoadLibrary(UC_CIPHER_LIB_PATH)

def test_fp(user_info):
    user_fp = create_string_buffer(32)
    uc_cipher.UCES_user_fingerprint(user_fp, user_info, 60)
    # print_key(user_fp)
    print(repr(user_info.value))
    print_key(user_fp)

def test_UCES_user_fingerprint():
    # To test UCES_user_fingerprint function by using string.
    print("Test UCES_user_fingerprint function")
    # TODO: to create a structure, instead of using a string only
    user_info1 = create_string_buffer("The user's information, including many things", 80)
    test_fp(user_info1)
    user_info2 = create_string_buffer("The user's information, including mamy things", 80)
    test_fp(user_info2)
    test_fp(user_info1)
    user_info3 = create_string_buffer("Whatever the string is, let's do it", 80)
    test_fp(user_info3)

def test_UCES_encrypt_content():
    print("_______________Test UCES_encrypt_buffer_________________")
    uc_enc_key = '\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70' \
                '\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80'
    buf = create_string_buffer("12345678901234567890123456789012" \
                                "qwertyuiopasdfghjklzxcvbnm[];,./")
    print(uc_enc_key)
    print_key(buf, 64)
    uc_cipher.UCES_encrypt_content(uc_enc_key, buf, 64)
    print_key(buf, 64)


def test_full_cycle(content, length):
    user_fp = create_string_buffer(32)
    client_pub_key = create_string_buffer(32)
    key_enc = create_string_buffer(32)
    key_dec = create_string_buffer(64)
    buf = create_string_buffer(content, length)
    random_buf = create_string_buffer(32)

    print("\n\n ======== Full Cycle Test Case =========")
    print("Original data - %d bytes (the 1st 32 bytes):"%length)
    print_key(content)

    # step 1: create user finger_print and create client pub_key
    user_info = "Username: steven; password='whatever';" \
                "userid: '1234567890'; register-date: 20180911"
    uc_cipher.UCES_user_fingerprint(user_fp, user_info, len(user_info))
    print("user_fingerprint:")
    print_key(user_fp)
    uc_cipher.UCES_client_pubkey(client_pub_key, user_fp, None);
    print("client_public_key:")
    print_key(client_pub_key)

    # step 2: create ciphering key and encrypt message
    uc_cipher.UCES_random_32(key_enc, 0x567890ab, 0xabcdef3456)
    print("ciphering key:")
    print_key(key_enc)
    uc_cipher.UCES_encrypt_content(key_enc, buf, length);
    print("Encoded data (the first 32 bytes):")
    print_key(buf)

    # step 3: Get decryption data
    uc_cipher.UCES_random_32(random_buf, 0x045903bf, 0xa8765f3456)
    uc_cipher.UCES_gen_decrypt_key(key_dec, random_buf, key_enc, client_pub_key)
    print("Ciphering key for client to decrypt data:")
    print_key(key_dec, 64)

    # step 4: decrypt data
    uc_cipher.UCES_decrypt_content(key_dec, buf, length, user_fp, None)
    print("Decrypted content (the first 32 bytes):")
    print_key(buf)

    if cmp(buf.value, content) == 0 :
        print("------- Bingo, everything is recovered, case PASSED! ------")
    else:
        print("------- Ooops, what's wrong! case FAILED --------")



if __name__ == '__main__':
    test_UCES_user_fingerprint()
    test_UCES_encrypt_content()
    content = "12345678901234567890123456789012" \
              "qwertyuiopasdfghjklzxcvbnm[];,./"
    test_full_cycle(content, 64)

    content = "abcdefghijklmnopqrstuvwxyz789012" * (1024*256/32)
    test_full_cycle(content, 256*1024)
