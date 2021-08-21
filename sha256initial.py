"""https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/
https://notebook.community/CraigLangford/Cryptographic-Functions/sha256/docs/SHA-256%20Basics%20in%20Python
https://medium.com/swlh/the-mathematics-of-bitcoin-74ebf6cefbb0

ppt - https://boingboing.net/2019/07/15/excellent-video-about-why-the.html"""


import math
import copy
import binascii

"""Step 1: preprocessing - convert to binary
#In Python, the ord() function accepts a string of unit length as an argument and returns the Unicode equivalence of the
# passed argument. In other words, given string of length 1, the ord() function returns an integer representing the
# Unicode code point of the character when the argument is a Unicode object, or the value of the byte when
# the argument is an 8-bit string.
# binary format"""

st = "hello world"
(' '.join(format(ord(x), 'b') for x in st))
#int = 10
# to convert an int to a binary number
#format(int, "b")


def convert_to_binary(data):
    """accepts string and integer input and convert to binary"""
    try:
        return ''.join(format(ord(x), '08b') for x in data)
    except:
        return format(data, "b")


def preprocess(data):
    """append 1 to the end ot the input"""
    appended_1 = str(data) + "1"
    # Pad with 0’s until data is a multiple of 512, less 64 bits
    num_zeroes = (512 + 448 - (len(appended_1) % 512))% 512
    padded = appended_1 + "0" * num_zeroes
    # Append 64 bits to the end, where the 64 bits are a big-endian integer representing the length of the original
    # input in binary.
    bin_len_input = format(len(data), "b")
    sixty_four_bit_binary = str(bin_len_input).zfill(64)
    # input should always be divisible by 512
    return padded + sixty_four_bit_binary

# hash_values - hese are hard-coded constants that represent the first 32 bits of the fractional parts of the square
# roots of the first 8 primes: 2, 3, 5, 7, 11, 13, 17, 19


def get_primes(count):
    primes_list = []
    n = 2
    while len(primes_list) != count:
        for i in range(2, n // 2 + 1):
            if n % i == 0:
                break
        else:
            primes_list.append(n)
        n += 1
    return primes_list


def hash_values():
    # get first 8 primes
    first_eight_primes = get_primes(8)
    # get fractional parts of square roots
    fractional_square_roots = [math.modf(math.sqrt(n))[0] for n in first_eight_primes]
    # multiply by 16^8 and take the floor
    floor = [math.floor(n * 16**8) for n in fractional_square_roots]
    # convert to hexadecimal
    first_eight_hash = [(hex(x), format(x, "b").zfill(32)) for x in floor]
    return first_eight_hash


def round_constants():
    first_sixty_four_primes = get_primes(64)
    # get fractional parts of cube roots of first 64 primes
    fractional_cube_roots = [math.modf(n ** (1. / 3.))[0] for n in first_sixty_four_primes]
    # multiply by 16^8 and take the floor
    floor = [math.floor(n * 16 ** 8) for n in fractional_cube_roots]
    # convert to hexadecimal
    first_sixty_four_hash = [(hex(x).zfill(8), format(x, "b").zfill(32)) for x in floor]
    return first_sixty_four_hash


def parse(data):
    # Copy the preprocessed data into a new array where each entry is a 32-bit word:
    # The block is then divided into words of 32-bits each:
    divide_512 = [data[i:i + 512] for i in range(0, len(data), 512)]
    message_schedule_array = []
    for string in divide_512:
        divide_32 = [string[i:i + 32] for i in range(0, len(string), 32)]
        print(divide_32)
        zeroes = "0" * 32
        # Add 48 more words initialized to zero, such that we have an array w[0…63]
        divide_32.extend(zeroes for i in range(48))
        message_schedule_array.append(divide_32)
    return message_schedule_array



def rotate_right(num, shift):
    # rotate num right by shift .  modified to use for strings of bits, works like rightwise bit shift
    #return (num >> shift) | (num << (size - shift))
    rotated = num[-shift:] + num[:-shift]
    return rotated


def shift_right(num, shift):
    # When shifting right with a logical right shift, the least-significant bit is lost and a 00 is inserted on the other end.
    rotated = "0" * shift + num[:-shift]
    return rotated

def NOT(a):
    ans = ""
    for i in range(len(a)):
        if a[i] == "1":
            ans += "0"
        else:
            ans += "1"
    return ans

def AND(a, b):
    # AND returns 1 if both bits are 1 else 0
    ans = ""
    for i in range(len(a)):
        # If the Character matches
        if a[i] == "1" and b[i] == "1":
            ans += "1"
        else:
            ans += "0"
    return ans


def xor(a, b):
    """XOR represents the inequality function, i.e., the output is true if the inputs are not alike otherwise the output is false. """
    ans = ""
    # Loop to iterate over the
    # Binary Strings
    for i in range(len(a)):

        # If the Character matches
        if (a[i] == b[i]):
            ans += "0"
        else:
            ans += "1"
    return ans

def maj(x, y, z):
    val1 = AND(x, y)
    val2 = AND(x, z)
    val3 = AND(y, z)
    return xor(xor(val1, val2), val3)


def ch(x, y, z):
    val1 = AND(x, y)
    val2 = AND(NOT(x), z)
    return xor(val1, val2)


def sigma_0(x):
    """First rotational + shifting mixing function"""
    σ_256_0 = xor(xor(rotate_right(x, 7), rotate_right(x, 18)), shift_right(x, 3))
    return σ_256_0

def sigma_1(x):
    """Second rotational + shifting mixing function"""
    σ_256_0 = xor(xor(rotate_right(x, 17), rotate_right(x, 19)), shift_right(x, 10))
    return σ_256_0

def epsilon_0(x):
    """First rotational mixing function"""
    σ_256_0 = xor(xor(rotate_right(x, 2), rotate_right(x, 13)), rotate_right(x, 22))
    return σ_256_0

def epsilon_1(x):
    """Second rotational mixing function"""
    σ_256_0 = xor(xor(rotate_right(x, 6), rotate_right(x, 11)), rotate_right(x, 25))
    return σ_256_0

def binary_add(a, b):
    max_len = max(len(a), len(b))
    a = a.zfill(max_len)
    b = b.zfill(max_len)

    # Initialize the result
    result = ''

    # Initialize the carry
    carry = 0

    # Traverse the string
    for i in range(max_len - 1, -1, -1):
        r = carry
        r += 1 if a[i] == '1' else 0
        r += 1 if b[i] == '1' else 0
        result = ('1' if r % 2 == 1 else '0') + result

        # Compute the carry.
        carry = 0 if r < 2 else 1

    if carry != 0:
        result = '1' + result

    return result.zfill(max_len)


def message_schedule(message):
    """For i from w[16…63]:
    s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
    s1 = (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
    w[i] = w[i-16] + s0 + w[i-7] + s1 """
    converted = convert_to_binary(message)
    processed = preprocess(converted)
    a = parse(processed)
    processed1 = []
    for k in range(len(a)):
        for i in range(16, len(a[0])):
            s0 = sigma_0(a[k][i - 15])
            s1 = sigma_1(a[k][i - 2])
            a[k][i] = binary_add(binary_add(binary_add(a[k][i - 16], s0), a[k][i - 7]), s1)[-32:]
            # only take last 32 chars
        final = a[k]
        processed1.append(final)
    return processed1

def compression_loop(message):
    h = [x[1] for x in hash_values()]
    # keep a copy for original values
    ho = copy.copy(h)
    k = [x[1] for x in round_constants()]
    w = message_schedule(message)
    print(w)
    #print(hash_vals)
    # compression loop mutate the values of a...h
    for j in range(len(w)):
        for i in range(0, 64):
            # copy list each loop
            hc = copy.copy(h)
            print("copy", hc)
            s1 = epsilon_1(hc[4])
            ch1 = ch(hc[4], hc[5], hc[6])
            val1 = binary_add(binary_add(hc[7], s1), ch1)
            val2 = binary_add(k[i], w[j][i])
            temp1 = binary_add(val1, val2)[-32:]
            # print(temp1)
            s0 = epsilon_0(hc[0])
            maj1 = maj(hc[0], hc[1], hc[2])
            temp2 = binary_add(s0, maj1)[-32:]
            # print(temp2)
            h[7] = hc[6]
            h[6] = hc[5]
            h[5] = hc[4]
            h[4] = binary_add(hc[3], temp1)[-32:]
            h[3] = hc[2]
            h[2] = hc[1]
            h[1] = hc[0]
            h[0] = binary_add(temp1, temp2)[-32:]
            print("modif", h)
    compressed_h = [binary_add(h[i], ho[i])[-32:] for i in range(len(h))]
    hex_vals = [hex(int(i, 2))[2:] for i in compressed_h]
    digest = ''.join(hex_vals)
    print(digest)


a = convert_to_binary("hello world")
print(len(preprocess(a)))

a = round_constants()
for i in a:
    print(len(i[0]))

