import math
import copy


class PreProcessData:
    """
    Taken from NIST:
    Preprocessing consists of three steps: padding the message, M (Sec. 5.1), parsing the message into message blocks
    (Sec. 5.2), and setting the initial hash value, H(0) (Sec. 5.3).

    for each block: 64 words of 32 bits each are constructed as follows:
    """
    BLOCK_SIZE = 64
    WORD_SIZE = 32

    def __init__(self, data):
        """Initialize the data to be stored.  Set pre-processed string to none"""
        self._data = data
        self.padded = None
        # initialize preprocessed data as an empty array
        self.preprocessed = []

    @property
    def data(self):
        """Property getter for data"""
        return self._data

    def convert_to_binary(self):
        """accepts string and integer inputs. Converts input to binary string"""
        try:
            return ''.join(format(ord(x), '08b') for x in self.data)
        except:
            print('Currently accepts string values only')

    def pad_data(self):
        """
        Ensure that the output has a length that is a multiple of 512 bits:
        1) append bit 1
        2) pad with 0's until data is a multiple of 512, less 64 bits.
        3) the length of the initial message is represented with exactly 64 bits, and these bits are added
        at the end of the message, giving us final message block of 512 bits.
        4) Block is divided into 16 words of 32 bits each.
        """
        # append 1 to the end ot the input"""
        appended_1 = str(self.convert_to_binary()) + "1"
        # Pad with 0’s until data is a multiple of 512, less 64 bits
        num_zeroes = (512 + 448 - (len(appended_1) % 512)) % 512
        padded = appended_1 + "0" * num_zeroes
        # Append 64 bits to the end, where the 64 bits are a big-endian integer representing the length of the original
        # input in binary.  Use zfill to left pad with 0s until length is 64
        bin_len_input = format(len(self.convert_to_binary()), "b")
        sixty_four_bit_binary = str(bin_len_input).zfill(self.BLOCK_SIZE)
        # Add the padded binary string with the 64 bit string representing length of original input
        self.padded = padded + sixty_four_bit_binary
        return self.padded

    def parse(self):
        """Parse data into equal lengths of 32"""
        # divide string into lengths of 32 (512/32 should give us 16)
        self.pad_data()
        # divide into N 512 bit blocks
        divide_512 = [self.padded[i:i + 512] for i in range(0, len(self.padded), 512)]
        for block in divide_512:
            divide_32 = [self.padded[i:i + self.WORD_SIZE] for i in range(0, len(block),self.WORD_SIZE)]
        # Add words initialized to zero so we have 64 words, such that we have an array w[0…63] to create out
        # "pre-message-schedule"
            divide_32.extend("0" * self.WORD_SIZE for _ in range(self.BLOCK_SIZE - len(divide_32)))
            self.preprocessed.append(divide_32)
        return self.preprocessed

    @staticmethod
    def hash_values():
        """Hard-coded constants that represent the first 32 bits of the fractional parts of the square roots of the first
        8 primes: 2, 3, 5, 7, 11, 13, 17, 19"""
        # get first 8 primes
        first_eight_primes = get_primes(8)
        # get fractional parts of square roots
        fractional_square_roots = [math.modf(math.sqrt(n))[0] for n in first_eight_primes]
        # multiply by 16^8 and take the floor
        floor = [math.floor(n * 16 ** 8) for n in fractional_square_roots]
        # convert to hexadecimal
        first_eight_hash = [('0x' + (hex(x)[2:].zfill(8)), format(x, "b").zfill(32)) for x in floor]
        return first_eight_hash

    @staticmethod
    def round_constants():
        """Hard-coded constants that represent the first 32 bits of the fractional parts of the cube
        roots of the first 64 primes (2 – 311)."""
        first_sixty_four_primes = get_primes(64)
        # get fractional parts of cube roots of first 64 primes
        fractional_cube_roots = [math.modf(n ** (1. / 3.))[0] for n in first_sixty_four_primes]
        # multiply by 16^8 and take the floor
        floor = [math.floor(n * 16 ** 8) for n in fractional_cube_roots]
        # convert to hexadecimal
        first_sixty_four_hash = [('0x' + (hex(x)[2:].zfill(8)), format(x, "b").zfill(32)) for x in floor]
        return first_sixty_four_hash


class SHA256:
    """Perform the block decomposition and hash computation to calculate final hash"""

    def __init__(self, data):
        # initialize the preprocessed data
        self.preprocessed = PreProcessData(data)
        self.hash_values = self.preprocessed.hash_values()
        self.round_constants = self.preprocessed.round_constants()
        # initialize message schedule to empty array
        self.message_schedule = []

    @staticmethod
    def maj(x, y, z):
        """Maj  stands for majority: for each bit index, that result bit is according to the majority of the 3
        inputs bits"""
        val1 = and_(x, y)
        val2 = and_(x, z)
        val3 = and_(y, z)
        return xor_(xor_(val1, val2), val3)

    @staticmethod
    def ch(x, y, z):
        """Ch stands for choose (source: poncho) or choice, as the 𝑥 input chooses if the output is from 𝑦 or from 𝑧."""
        val1 = and_(x, y)
        val2 = and_(not_(x), z)
        return xor_(val1, val2)

    @staticmethod
    def sigma_0(x):
        """First rotational + shifting mixing function"""
        s_0 = xor_(xor_(rotate_right(x, 7), rotate_right(x, 18)), shift_right(x, 3))
        return s_0

    @staticmethod
    def sigma_1(x):
        """Second rotational + shifting mixing function"""
        s_1 = xor_(xor_(rotate_right(x, 17), rotate_right(x, 19)), shift_right(x, 10))
        return s_1

    @staticmethod
    def epsilon_0(x):
        """First rotational mixing function"""
        e_0 = xor_(xor_(rotate_right(x, 2), rotate_right(x, 13)), rotate_right(x, 22))
        return e_0

    @staticmethod
    def epsilon_1(x):
        """Second rotational mixing function"""
        e_1 = xor_(xor_(rotate_right(x, 6), rotate_right(x, 11)), rotate_right(x, 25))
        return e_1

    def block_decomposition(self):
        """
        Prepare the message schedule (aka mutate the zeroes from pre-message-schedule produced in preprocessing):
        For i from w[16…63]:
        s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        s1 = (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
        w[i] = w[i-16] + s0 + w[i-7] + s1 """
        # pre_process and parse the data to retrieve the message block
        preprocessed = self.preprocessed.parse()
        # for each 512-bit block message schedule
        for h in range(len(preprocessed)):
            for i in range(16, len(preprocessed[0])):
                # mutate the blocks of zeroes from w[16] to w[63] using s0 and s1 functions
                s0 = self.sigma_0(preprocessed[h][i - 15])
                s1 = self.sigma_1(preprocessed[h][i - 2])
                preprocessed[h][i] = binary_add(binary_add(binary_add(preprocessed[h][i - 16], s0), preprocessed[h][i - 7]),
                                              s1)
            self.message_schedule.append(preprocessed[h])
        return self.message_schedule


    def generate_hash(self):
        """Run the compression loop to generate the final hash"""
        # get hash_values and round_constants
        h = [x[1] for x in self.hash_values]
        k = [x[1] for x in self.round_constants]
        # keep a copy of original hash values
        ho = copy.copy(h)
        # get the message schedule
        w = self.block_decomposition()
        # print(hash_vals)
        # compression loop mutate the values of a...h
        for i in range(len(w)):
            for j in range(0, 64):
                # copy list for each loop round
                hc = copy.copy(h)
                s1 = self.epsilon_1(hc[4])
                ch1 = self.ch(hc[4], hc[5], hc[6])
                val1 = binary_add(binary_add(hc[7], s1), ch1)
                val2 = binary_add(k[j], w[i][j])
                temp1 = binary_add(val1, val2)
                # print(temp1)
                s0 = self.epsilon_0(hc[0])
                maj1 = self.maj(hc[0], hc[1], hc[2])
                temp2 = binary_add(s0, maj1)
                # print(temp2)
                h[7] = hc[6]
                h[6] = hc[5]
                h[5] = hc[4]
                h[4] = binary_add(hc[3], temp1)
                h[3] = hc[2]
                h[2] = hc[1]
                h[1] = hc[0]
                h[0] = binary_add(temp1, temp2)
        # add final values hash values at end of iteration to original hash values
        compressed_h = [binary_add(h[x], ho[x]) for x in range(len(h))]
        # convert hash values to hex and concatenate them
        hex_vals = [(hex(int(x, 2))[2:]).zfill(8) for x in compressed_h]
        digest = ''.join(hex_vals)
        # return the final hash output (in hex)
        print(digest)
        return digest


def get_primes(count):
    """Function to get n=count primes"""
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


def rotate_right(num, shift):
    # rotate num right by shift .  modified to use for strings of bits, works like bitwise bit shift
    # return (num >> shift) | (num << (size - shift))
    rotated = num[-shift:] + num[:-shift]
    return rotated


def shift_right(num, shift):
    # When shifting right with a logical right shift, the least-significant bit is lost and a 00 is inserted on the
    # other end.
    rotated = "0" * shift + num[:-shift]
    return rotated


def not_(a):
    """Bitwise NOT string implementation"""
    ans = ""
    for i in range(len(a)):
        if a[i] == "1":
            ans += "0"
        else:
            ans += "1"
    return ans


def and_(a, b):
    """Bitwise AND string implementations"""
    ans = ""
    for i in range(len(a)):
        # If both characters are equal to 1, add 1 to string, else add 0
        if a[i] == "1" and b[i] == "1":
            ans += "1"
        else:
            ans += "0"
    return ans


def xor_(a, b):
    """XOR represents the inequality function, i.e., the output is true if the inputs are not alike otherwise the
    output is false. """
    ans = ""
    # initiate for loop to iterate over the binary string
    for i in range(len(a)):
        # If the characters match, add 0 to ans, else add 1 for each character
        if a[i] == b[i]:
            ans += "0"
        else:
            ans += "1"
    return ans


def binary_add(a, b):
    length = max(len(a), len(b))
    a = a.zfill(length)
    b = b.zfill(length)
    # Initialize sum as empty string
    sum = ''
    # initialize carry = 0
    carry = 0
    # Traverse the string
    for i in range((length - 1), -1, -1):
        rem = carry
        rem += 1 if a[i] == '1' else 0
        rem += 1 if b[i] == '1' else 0
        sum = ('1' if rem % 2 == 1 else '0') + sum
        # calc carry
        if rem <= 1:
            carry = 0
        else:
            carry = 1
    if carry != 0:
        sum = '1' + sum
    # binary addition is calculated modulo 2^32
    return sum.zfill(length)[-32:]

