from ctypes import *



def print_key(key, length=32):
    print("key:")
    for i in xrange(length):
        print("%x"%(key.value[i])) ,
    print("\n")

uc_cipher = cdll.LoadLibrary("/home/steven004/uc_cipher/uc_cipher.so")

def test_fp(user_info):
    user_fp = create_string_buffer(32)
    uc_cipher.UCES_user_fingerprint(user_fp, user_info, 80)
    # print_key(user_fp)
    print(repr(user_info.raw))
    print(repr(user_fp.raw), '\n')

if __name__ == '__main__':
    user_info1 = create_string_buffer("The user's information, including many things", 80)
    test_fp(user_info1)
    user_info2 = create_string_buffer("The user's information, including mamy things", 80)
    test_fp(user_info2)
    test_fp(user_info1)

    user_info3 = create_string_buffer("Whatever the string is, let's do it", 80)
    test_fp(user_info3)
    
