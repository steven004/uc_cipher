from ctypes import *

UC_CIPHER_LIB_PATH = "/home/steven004/uc_cipher/uc_cipher.so"

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
    // TODO: to create a structure, instead of using a string only
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



if __name__ == '__main__':
    test_UCES_user_fingerprint()
    test_UCES_encrypt_content()
