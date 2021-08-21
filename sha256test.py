'''
Sara Lee
Unit test cases for methods in SHA256.py and performance tests
I used sample data from:
https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/ to verify data
to compare and verify each step for "hello world"
I also referenced hashlib sha256 to compare hashes produced by my SHA256 class with hashes produced by python
hashlib.
Finally, I ran some performance tests for my SHA256 class vs python hashlib SHA256. I also ran performance
tests for hashlib SHA-256 vs SHA-512 for varying length strings.
'''


import unittest
from sha256 import *
import hashlib
import random
import itertools
import timeit
from string import ascii_uppercase, digits, ascii_lowercase


class PreProcessDataTestCase(unittest.TestCase):
    """Test that data is preprocessed correctly - check padding, lengths, and compare with input data"""

    def setUp(self):
        self.str_test_case = PreProcessData("hello world")

    def testConvertToBinary(self):
        """test that int and string are properly converted to binary"""
        self.assertEqual(self.str_test_case.convert_to_binary(), '01101000011001010110110001101100011011110010000001110111'
                                                            '01101111011100100110110001100100')
        print(f"Original String: {self.str_test_case.data}\n")
        print(f"String in Binary: {self.str_test_case.convert_to_binary()}\n")

    def testPreProcess(self):
        # assert that length is 64
        self.assertEqual(len(self.str_test_case.parse()[0]), 64)
        # each val in preprocessed array should have a length of 32
        for i in self.str_test_case.parse()[0]:
            self.assertEqual(len(i), 32)
        # 16th value should equal '01011000', also test first and last values match sample data
        self.assertEqual(self.str_test_case.preprocessed[0][0], '01101000011001010110110001101100')
        self.assertEqual(self.str_test_case.preprocessed[0][15], '00000000000000000000000001011000')
        self.assertEqual(self.str_test_case.preprocessed[0][63], '00000000000000000000000000000000')
        print('Pre-Processed Data:')
        print(self.str_test_case.preprocessed, "\n")

    def testHashValues(self):
        """Make sure correct hash values were generated - compare to original values provided by NIST"""
        test = self.str_test_case.hash_values()
        # these are the hash values provided by NIST
        expected = [
            '0x6a09e667',
            '0xbb67ae85',
            '0x3c6ef372',
            '0xa54ff53a',
            '0x510e527f',
            '0x9b05688c',
            '0x1f83d9ab',
            '0x5be0cd19',
        ]
        for i in range(8):
            self.assertEqual(test[i][0], expected[i])

    def testRoundConstants(self):
        """Make sure correct round constants were generated - compare to official values provided by NIST"""
        test = self.str_test_case.round_constants()
        expected = [
             '0x428a2f98', '0x71374491', '0xb5c0fbcf', '0xe9b5dba5', '0x3956c25b', '0x59f111f1', '0x923f82a4',
             '0xab1c5ed5', '0xd807aa98', '0x12835b01', '0x243185be', '0x550c7dc3', '0x72be5d74', '0x80deb1fe',
             '0x9bdc06a7', '0xc19bf174', '0xe49b69c1', '0xefbe4786', '0x0fc19dc6', '0x240ca1cc', '0x2de92c6f',
             '0x4a7484aa', '0x5cb0a9dc', '0x76f988da', '0x983e5152', '0xa831c66d', '0xb00327c8', '0xbf597fc7',
             '0xc6e00bf3', '0xd5a79147', '0x06ca6351', '0x14292967', '0x27b70a85', '0x2e1b2138', '0x4d2c6dfc',
             '0x53380d13', '0x650a7354', '0x766a0abb', '0x81c2c92e', '0x92722c85', '0xa2bfe8a1', '0xa81a664b',
             '0xc24b8b70', '0xc76c51a3', '0xd192e819', '0xd6990624', '0xf40e3585', '0x106aa070', '0x19a4c116',
             '0x1e376c08', '0x2748774c', '0x34b0bcb5', '0x391c0cb3', '0x4ed8aa4a', '0x5b9cca4f', '0x682e6ff3',
             '0x748f82ee', '0x78a5636f', '0x84c87814', '0x8cc70208', '0x90befffa', '0xa4506ceb', '0xbef9a3f7',
             '0xc67178f2'
        ]
        for i in range(64):
            self.assertEqual(test[i][0], expected[i])


class FunctionsTestCase(unittest.TestCase):
    """Test binary operations"""

    def testNotAndXor(self):
        """Make sure that not and and xor work as intended"""
        test_str = '10101010'
        test_str_2 = '00101000'
        self.assertEqual(not_(test_str), '01010101')
        self.assertEqual(and_(test_str, test_str_2), '00101000')
        self.assertEqual(xor_(test_str, test_str_2), '10000010')

    def testRotateRight(self):
        """Make sure that right rotations work as intended"""
        self.assertEqual(rotate_right('0010101010', 2), '1000101010')
        self.assertEqual(rotate_right('00101010100010101010', 3), '01000101010100010101')

    def testShiftRight(self):
        """Make sure that right rotations work as intended"""
        self.assertEqual(shift_right('0010101010', 2), '0000101010')
        self.assertEqual(shift_right('00101010100010101010', 3), '00000101010100010101')


class SHA256TestCase(unittest.TestCase):
    """Test that class SHA256 outputs the correct digest"""

    def setUp(self):
        self.test_case = SHA256("hello world")

    def testBlockDecomposition(self):
        """Test that correct message schedule is produced after block decomposition phase"""
        # assert that length of message schedule is 64
        self.assertEqual(len(self.test_case.block_decomposition()[0]), 64)

        # each block in the message schedule should have a length of 32
        for i in self.test_case.block_decomposition()[0]:
            self.assertEqual(len(i), 32)
        # compare with the sample data
        self.assertEqual(self.test_case.block_decomposition()[0][0], '01101000011001010110110001101100')
        self.assertEqual(self.test_case.block_decomposition()[0][63], '11000010110000101110101100010110')
        self.assertEqual(self.test_case.block_decomposition()[0][1], '01101111001000000111011101101111')
        self.assertEqual(self.test_case.block_decomposition()[0][62], '11111100000101110100111100001010')
        for i in range(3, 13):
            self.assertEqual(self.test_case.block_decomposition()[0][i], '00000000000000000000000000000000')
        print("Data after Block Decomposition:")
        print(self.test_case.block_decomposition(), "\n")


    def testDigestHelloWorld(self):
        # assert that the generated hash for "hello world" is the same as python hashlib library
        self.assertEqual(self.test_case.generate_hash(), hashlib.sha256("hello world".encode("ascii")).hexdigest())

    def testDigestRandomLib(self):
        # let's test for 1000 random strings of upper and lowercase digits
        # from length 0 to 20 to ensure string will be less < 512 bits
        for i in range(1000):
            test_str = ''.join(random.choice(ascii_uppercase + digits + ascii_lowercase) for _ in
                               range(random.randint(0, 20)))
            test = SHA256(test_str)
            # call SHA 256 library
            self.assertEqual(test.generate_hash(), hashlib.sha256(test_str.encode("ascii")).hexdigest())
        print("Tests passed for 1000 random words")


class SHA256PerformanceTestCase(unittest.TestCase):
    """Performance tests for my SHA256 class, hashlib SHA256, and hashlib SHA256"""

    def testPerformanceSHA256My(self):
        """test performance times or my SHA-256 class"""
        # generate test_str f length 20
        test_str = ''.join(random.choice(ascii_uppercase + digits + ascii_lowercase) for _ in
                           range(20))
        print("Performance Tests for My SHA256")
        test = SHA256(test_str)
        for length in itertools.chain([10, 100, 500], range(1000, 2500, 500)):
            duration = timeit.timeit(lambda: test.generate_hash(), number=length)
            print(f"n={length}: {duration}")

    def testPerformanceSHA256(self):
        """test performance times for hashlib sha-256 for length 20 strings"""
        # generate test_str of length 20
        test_str = ''.join(random.choice(ascii_uppercase + digits + ascii_lowercase) for _ in
                           range(20))
        print("Performance Tests for SHA-256 length 20 string")
        n = 100
        while n < 10000000:
            duration = timeit.timeit(lambda: hashlib.sha256(test_str.encode("ascii")).hexdigest(), number=n)
            n *= 4
            print(f"n={n}: {duration}")

    def testPerformance512(self):
        """test performance times for hashlib sha-512 for length 20 strings"""
        # generate test_str of length 20 strings
        test_str = ''.join(random.choice(ascii_uppercase + digits + ascii_lowercase) for _ in
                           range(20))
        print("Performance Tests for SHA-512 length 20 string")
        test = SHA256(test_str)
        n = 100
        while n < 10000000:
            duration = timeit.timeit(lambda: hashlib.sha512(test_str.encode("ascii")).hexdigest(), number=n)
            n *= 4
            print(f"n={n}: {duration}")


    def testPerformanceSHA256(self):
        """test performance times for hashlib sha-256 for length 10000000 strings"""
        # generate test_str of length 10000000 strings
        test_str = ''.join(random.choice(ascii_uppercase + digits + ascii_lowercase) for _ in
                           range(10000000))
        print("Performance Tests for SHA-256 length 10000000 string")
        n = 10
        while n < 4000:
            duration = timeit.timeit(lambda: hashlib.sha256(test_str.encode("ascii")).hexdigest(), number=n)
            print(f"n={n}: {duration}")
            n *= 4

    def testPerformance512(self):
        """test performance times for hashlib sha-512 for length 10000000 strings"""
        # generate test_str of length 10000000 strings
        test_str = ''.join(random.choice(ascii_uppercase + digits + ascii_lowercase) for _ in
                           range(10000000))
        print("Performance Tests for SHA-512 length 10000000 string ")
        test = SHA256(test_str)
        n = 10
        while n < 4000:
            duration = timeit.timeit(lambda: hashlib.sha512(test_str.encode("ascii")).hexdigest(), number=n)
            print(f"n={n}: {duration}")
            n *= 4

'''

Performance test results:

My SHA-256 is multitudes slower than hashlib SHA-256.  One reason may be that I fed binary strings into each function 
(rather than binary numbers) which most likly slowed down performance.  In addition, upon research, python hashlib 
was optimized for fast performance using C implementation.  

I also decided to run a performance test for SHA-256 and SHA-512 for short vs "long" string sizes.  F
From research paper linked below, 
"The performance of SHA-256 and SHA-512 depends on the length of the hashed message.  The reason why SHA-512 is faster 
than SHA-256 on 64-bit machines is that has 37.5% less rounds per byte (80
rounds operating on 128 byte blocks) compared to SHA256 (64 rounds operating on 64 byte blocks), where the
operations use 64-bit integer arithmetic." In performance tests, when comparing SHA-256 and SHA-512, SHA-256 is 
slightly faster for shorter string hashes whereas SHA-512 is  slightly faster for hashing longer strings.  
This is due to the fact that SHA-512 is in fact slower per 
iteration, but uses twice the block size as SHA-256. 
https://eprint.iacr.org/2010/548.pdf

Performance Tests for My SHA256
n=10: 0.19714482600000238
n=100: 1.574601664000003
n=500: 8.976057681
n=1000: 14.006582980000005
n=1500: 26.698070706999992
n=2000: 33.500114106
n=2500: 40.51711310100001

Performance Tests for SHA-512 length 20 string 
n=400: 0.00046164099999998487
n=1600: 0.0006825160000000219
n=6400: 0.006420521000000012
n=25600: 0.012320216999999994
n=102400: 0.055093685999999975
n=409600: 0.17529464299999997
n=1638400: 0.673528578
n=6553600: 2.757741159
n=26214400: 11.119608703

Performance Tests for SHA-256 length 20 string 
n=400: 0.00014948699999983717
n=1600: 0.0005459900000008844
n=6400: 0.0021057879999997198
n=25600: 0.012334121000000309
n=102400: 0.03584557799999999
n=409600: 0.1805451490000003
n=1638400: 0.5889075199999994
n=6553600: 2.395786501
n=26214400: 11.652971480000001

Performance Tests for SHA-512 length 10000000 string 
n=10: 0.20861409299999956
n=40: 0.7800558300000002
n=160: 3.121173045000001
n=640: 12.380577397
n=2560: 61.22908305600001


Performance Tests for SHA-256 length 10000000 string
n=10: 0.2787120899999991
n=40: 1.1083117270000002
n=160: 4.444356759999998
n=640: 17.817176263999997
n=2560: 101.22908305600001
'''













