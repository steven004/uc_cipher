from ctypes import *


def print_key(key, length=32):
    print("key:")
    for i in xrange(length):
        print("%x"%(key.value[i])) ,
    print("\n")

if __name__ == '__main__':
    uc_cipher = cdll.LoadLibrary("/Users/zxm/Documents/temptemp/uc_cipher.so")
    user_info = create_string_buffer("The user's information, including many things", 80)
    user_fp = create_string_buffer(32)

    uc_cipher.UCES_user_fingerprint(user_fp, user_info, 80)

    print_key(user_fp)
