# SHA-256
Pure Python SHA-256 implementation

Follows algorithm outlined in:
https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf

Link to presentation on SHA-256:
https://docs.google.com/presentation/d/18nNsViKdaeZT40VWtH7bFTEZ-1E0iF4NzJYYXBOiNFE/edit?usp=sharing

Pure python implementation of the SHA-256 hash function, organized using object oriented programming methods.
My goal for this project was to organize SHA-256 into readable code and user-friendly classes.  (Note: Not meant to optimize speed) 
Class PreProcess data contains the three steps provided by NIST to preprocess a string:  1) padding, 2)parsing, and 3) generating hash values and round constants.
Class SHA256 calls class PreProcessData to initialize the preprocessed data, parses it, and runs the message block through block decomposition algorithm to retrieve the message schedule.  Then, using the generated message schedule, hash value constants, and round constants, the hash is generated in generate_hash() following
algorithm provided by NIST.  Supporting functions for s1, s0, ch, and maj operations are also defined in class SHA256.

