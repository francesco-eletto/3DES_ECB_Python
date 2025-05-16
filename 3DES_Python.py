OUT_PATH = "out.txt"

ROUNDS_NUM = 16
S_BOX_NUM = 8
S_BOX_OUTPUT_LEN = 4
S_BOX_INPUT_LEN = 6
BLOCK_LEN = 64
XOR_BLOCK_LEN = 48
KEY_LENGTH = 64
KEY_STRIPPED_LENGTH = 56

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IIP = [40, 8, 48, 16, 56, 24, 64, 32,
       39, 7, 47, 15, 55, 23, 63, 31,
       38, 6, 46, 14, 54, 22, 62, 30,
       37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28,
       35, 3, 43, 11, 51, 19, 59, 27,
       34, 2, 42, 10, 50, 18, 58, 26,
       33, 1, 41, 9, 49, 17, 57, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

S_BOXES = [
    # S-box 1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    # S-box 2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    # S-box 3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    # S-box 4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    # S-box 5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    # S-box 6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    # S-box 7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    # S-box 8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]


def string_to_bin_string(text):
    return ''.join(format(ord(char), '08b') for char in text)


def bin_string_to_string(bin_string):
    text = ''.join(chr(int(bin_string[i:i + 8], 2)) for i in range(0, len(bin_string), 8))
    return text


def xor_strings(bin_str1, bin_str2):
    return ''.join(['1' if b1 != b2 else '0' for b1, b2 in zip(bin_str1, bin_str2)])


def int_to_bin_string(int, length):
    return bin(int)[2:].zfill(length)


def bin_left_pad(bin_str):
    padding_length = (BLOCK_LEN - len(bin_str) % BLOCK_LEN) % BLOCK_LEN
    return '0' * padding_length + bin_str


def pad_spaces_bin(bin_text):
    padding_needed = BLOCK_LEN - (len(bin_text) % BLOCK_LEN)
    if padding_needed == BLOCK_LEN:
        return bin_text

    space_bin = '00100000'

    bin_padding = space_bin * (padding_needed // 8)
    return bin_text + bin_padding


def apply_table(bin_string, table):
    result = ""
    # print(bin_string)

    for i in range(len(table)):
        result += bin_string[table[i] - 1]

    return result


def rotate_left(bin_string, rotate_ammount):
    rotated_bin_string = bin_string[rotate_ammount:] + bin_string[:rotate_ammount]
    return rotated_bin_string


def generate_subkeys(bin_key):
    results = {}

    permuted_bin_key = apply_table(bin_key, PC1)
    # print(permuted_bin_key)

    permuted_bin_key_left = permuted_bin_key[0:KEY_STRIPPED_LENGTH // 2]
    permuted_bin_key_right = permuted_bin_key[KEY_STRIPPED_LENGTH // 2:]

    # print(permuted_bin_key_left)
    # print(permuted_bin_key_right)
    # print("")

    for i in range(16):
        if i == 0 or i == 1 or i == 8 or i == 15:
            permuted_bin_key_left = rotate_left(permuted_bin_key_left, 1)
            permuted_bin_key_right = rotate_left(permuted_bin_key_right, 1)

            # print(permuted_bin_key_left)
            # print(permuted_bin_key_right)
            # print("")

        else:
            permuted_bin_key_left = rotate_left(permuted_bin_key_left, 2)
            permuted_bin_key_right = rotate_left(permuted_bin_key_right, 2)

            # print(permuted_bin_key_left)
            # print(permuted_bin_key_right)
            # print("")

        round_bin_key = permuted_bin_key_left + permuted_bin_key_right
        round_bin_key = apply_table(round_bin_key, PC2)
        results[i] = round_bin_key

    return results


def s_translate(bin_string, S_TABLE):
    row = int(bin_string[0:1] + bin_string[-1], 2)
    col = int(bin_string[1:-1], 2)

    s_result = S_TABLE[row][col]

    s_bin_result = int_to_bin_string(s_result, S_BOX_OUTPUT_LEN)

    return s_bin_result


def f_function(bin_block, bin_round_key):
    expanded_bin_block = apply_table(bin_block, E)

    # xor_result = int(expanded_bin_block, 2) ^ int(bin_round_key, 2)
    # xor_bin_result = int_to_bin_string(xor_result, XOR_BLOCK_LEN)

    xor_bin_result = xor_strings(expanded_bin_block, bin_round_key)

    s_bin_block = ""
    for i in range(0, S_BOX_NUM):
        j = i * S_BOX_INPUT_LEN
        s_bin_block += s_translate(xor_bin_result[j:j + S_BOX_INPUT_LEN], S_BOXES[i])

    permuted_s_bin_block = apply_table(s_bin_block, P)

    return permuted_s_bin_block


def encrypt_block(bin_block, bin_keys, mode):
    permuted_bin_block = apply_table(bin_block, IP)

    round_bin_block_out_left = ""
    round_bin_block_out_right = ""

    round_bin_block_in_left = permuted_bin_block[0:BLOCK_LEN // 2]
    round_bin_block_in_right = permuted_bin_block[BLOCK_LEN // 2:]

    for i in range(ROUNDS_NUM):
        f_bin_block_right = ""

        if mode == 1:
            f_bin_block_right = f_function(round_bin_block_in_right, bin_keys[i])
        elif mode == 0:
            f_bin_block_right = f_function(round_bin_block_in_right, bin_keys[ROUNDS_NUM - 1 - i])

        round_bin_block_out_left = round_bin_block_in_right
        # round_bin_block_out_right = int_to_bin_string(int(round_bin_block_in_left, 2) ^ int(f_bin_block_right, 2),
        #                                               int(BLOCK_LEN / 2))
        round_bin_block_out_right = xor_strings(round_bin_block_in_left, f_bin_block_right)

        round_bin_block_in_left = round_bin_block_out_left
        round_bin_block_in_right = round_bin_block_out_right

    rounds_out_bin_block = apply_table(round_bin_block_out_right + round_bin_block_out_left, IIP)

    return rounds_out_bin_block


def des(bin_string, bin_key, mode):
    if len(bin_key) != KEY_LENGTH:
        print("key length should be 8 bytes!")
        exit()

    bin_keys = generate_subkeys(bin_key)
    # print(bin_keys)
    if mode == 0:
        bin_string = bin_left_pad(bin_string)
    else:
        bin_string = pad_spaces_bin(bin_string)

    plain_text_len = len(bin_string)
    encrypted_result = ""

    for i in range(0, plain_text_len, BLOCK_LEN):
        bin_block = bin_string[i:i + BLOCK_LEN]
        encrypted_result += encrypt_block(bin_block, bin_keys, mode)

    return encrypted_result


def tdes_decrypt(cipher_text, key):
    for i in range(3):
        cipher_text = des(cipher_text, key, 0)
    return cipher_text

def tdes_encrypt(plain_text, key):
    for i in range(3):
        plain_text = des(plain_text, key, 1)
    return plain_text

if __name__ == '__main__':

    fin_path = ""

    mode_choice = input("encrypt(0) || decrypt(1): ")
    if mode_choice == "0":
        fin_path = input("path of input file(plain text): ")
    elif mode_choice == "1":
        fin_path = input("path of input file(hexadecimal): ")
    else:
        print("Error - choice doesn't exists!")
        exit()


    fout_path = OUT_PATH
    input_text = ""
    plain_key = ""


    try:
        fin = open(fin_path, mode="r")
        input_text = fin.read()
    except:
        print("Error - input file doesn't exists!")
        exit()

    k_choice = input("in-line key(0) || file-key(1): ")

    if k_choice == "0":
        plain_key = input("enter your key(plain text): ")
    elif k_choice == "1":
        fkey_path = input("path of key file(plain text): ")
        try:
            fkey = open(fkey_path, mode="r")
            plain_key = fkey.read()
        except:
            print("Error - key file doesn't exists!")
            exit()
    else:
        print("Error - choice doesn't exists!")
        exit()

    print("--------------------------")
    if mode_choice == "0":
        cipher_text = tdes_encrypt(string_to_bin_string(input_text), string_to_bin_string(plain_key))

        if (cipher_text != None):
            print("Encrypted text(hexadecimal): " + hex(int(cipher_text, 2))[2:])
            try:
                fout = open(fout_path, "w")
                fout.write(hex(int(cipher_text, 2))[2:])
            except:
                print("Error - cannot write on output")
                exit()
    elif mode_choice == "1":
        bin_cipher_text = bin(int(input_text, 16))[2:]
        decrypted_text = tdes_decrypt(bin_cipher_text, string_to_bin_string(plain_key))

        if (decrypted_text != None):
            print("Decrypted text: " + bin_string_to_string(decrypted_text))
            try:
                fout = open(fout_path, "w")
                fout.write(bin_string_to_string(decrypted_text))
            except:
                print("Error - cannot write on output")
                exit()
