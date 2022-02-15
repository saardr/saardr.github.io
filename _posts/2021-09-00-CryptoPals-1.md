---
title: CryptoPals Set 1 writeup - Cracking repeating key XOR
date: 2021-09
categories:
    - crypto
    - programming
tags:
    - CryptoPals Set 1 writeup
    - Cracking repeating key XOR
---


# CryptoPals challenges 1-6 writeups -  vinegre cipher

#### the following are my solutions + explanations to the first set of the cryptopals challenges, other set solutions can be found at my [github](https://github.com/lordofswords)

## challenge 1: Convert hex to base64

[<strong> description</strong>](https://cryptopals.com/sets/1/challenges/1): <br> 
> The string: *49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d* <br><br>
Should produce: *SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t*

in other words, we decode a b64 string and then hex it. this quite simple to do in python.

quick explanation of how base64 works:
take 6 bits every time and convert them to their equivalent b64 encoding.
usually you would take 8 bits. $ 2^8 = 256 $. $ 2^6 = 64 $, hence base 64. for instance:
"wow" = "\b01110111\b01101111\b01110111" -> "011101 110110 111101 110111" -> 
29 54 61 55 -> (looking up values in [b64 table](https://en.wikipedia.org/wiki/Base64) -> "d293"

this can be simply implemented in python, however for simplicity & efficienct i will use the built in libary [`base64`](https://docs.python.org/3/library/base64.html)


```python
from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify

hex2b64 = lambda b64_s: hexlify(b64decode(b64_s))
b64_2_hex = lambda hex_s: b64encode(unhexlify(hex_s))
```


```python
b64_2_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
```




    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'




```python
hex2b64('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')
```




    b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'



## challenge 2: Fixed-XOR

[<strong> description</strong>](https://cryptopals.com/sets/1/challenges/2): <br> 
> Write a function that takes two equal-length buffers and produces their XOR combination. <br><br>
If your function works properly, then when you feed it the string: <br><br>
*1c0111001f010100061a024b53535009181c* <br><br>
... after hex decoding, and when XOR'd against: <br><br>
*686974207468652062756c6c277320657965* <br><br>
... should produce: <br><br>
*746865206b696420646f6e277420706c61798* """

again, a rather simple challenge, we just use python built in xor. notice: the strings are in hex format, so we also need to unhexlify them. <br> this is a good time to mention - all challenges were solved using python built in <i> bytes </i> rather than the default utf-8 strings.

from the docs: 
- [`bytes`](https://docs.python.org/3/library/stdtypes.html#bytes): "Bytes objects are immutable sequences of single bytes", basically - normal string but based on ascii encoding as was in python2 rather than utf-8 encoding.
bytearray - "bytearray objects are a mutable counterpart to bytes objects", self explanatory.


```python
from binascii import hexlify, unhexlify

def fixed_hex_XOR(s1_hex, s2_hex) -> bytes:
    s1 = unhexlify(s1_hex)
    s2 = unhexlify(s2_hex)
    res = bytearray([b1^b2 for b1, b2 in zip(s1, s2)])
    return hexlify(res)

def fixed_XOR(s1 : bytes, s2 : bytes) -> bytes: # for non-hex strings
    return bytes([b1^b2 for b1, b2 in zip(s1, s2)])
```


```python
fixed_hex_XOR("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
```




    b'746865206b696420646f6e277420706c6179'



small note - zip takes several iterables and combines their iterators into one. taking the next element out of each, alternating between them. finishes when the smallest iterator is consumed.

## challenge 3: Single-byte XOR cipher

[<strong> description</strong>](https://cryptopals.com/sets/1/challenges/3): <br>
> The hex encoded string: *1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736* <br><br>
... has been XOR'd against a single character. Find the key, decrypt the message.

this is where the challenges begin getting fun and intresting.
our plan of attack is the following: <br>
1. come up with a scoring function for candidate bytes, i used a letter freq dictionary as the basis for it, higher score = less likely to be correct <br>
2. calculate the scoring for every byte in the ascii table (so from 0 to 127), store the results in a dictionary for       quick access. <br>
3. pick the 2 (custom) smallest elements from said dictionary, if the scoring function was good enough the result will be           there. <br>
4. decrypt the string using one of the resulting bytes from step 3 (just XOR again since $ a \oplus b = c \implies a \oplus c = b $)

coming up with a good scoring function is what i found to be the trickiest part. this is what i came up with after some twicking:


```python
eng_letter_freq = { # https://en.wikipedia.org/wiki/Letter_frequency
    ord('a') : 8.2,
    ord('b') : 1.5,
    ord('c') : 2.8,
    ord('d') : 4.3,
    ord('e') : 13.0,
    ord('f') : 2.2,
    ord('g') : 2.0,
    ord('h') : 6.1,
    ord('i') : 7.0,
    ord('j') : 0.15,
    ord('k') : 0.77,
    ord('l') : 4.0,
    ord('m') : 2.4,
    ord('n') : 6.7,
    ord('o') : 7.5,
    ord('p') : 1.9,
    ord('q') : 0.095,
    ord('r') : 6.0,
    ord('s') : 6.3,
    ord('t') : 9.1,
    ord('u') : 2.8,
    ord('v') : 0.98,
    ord('w') : 2.4,
    ord('x') : 0.15,
    ord('y') : 2.0,
    ord('z') : 0.074,
    ord(' ') : 1/6
}

from collections import Counter
import string

def evaluate(s):
    total = 0
    d = dict(Counter(s))
    for letter in set(d.keys()).union(set(eng_letter_freq.keys())):
        if letter not in eng_letter_freq and chr(letter) not in string.digits:
            total += 1
        total += abs(d.get(letter, 0)/len(s) - eng_letter_freq.get(letter, 0)/100)**0.5
    return total
```

First, it takes a string and stores its letter-count using python built-in Counter (https://docs.python.org/3/library/collections.html#collections.Counter). <br>
it then increases the score based on the char freq in s vs the freq dict and some calculations. notice that if the char is not in the dict altogether, the score is increased more significantly.

Undoubtly, this can be improved, and by a lot. further and perhaps better normalization could be done. however it has proved itself sufficient enough for the challenges.

the rest of the code as decribed in steps 2-4:


```python
from binascii import unhexlify
import heapq

xor_encrypt = lambda s, xor_key: bytearray([b^xor_key for b in s])

def break_single_byte_xor(s_hex, guess_cnt = 2): # returns [guess_cnt] keys
    s = unhexlify(s_hex)
    res_dict = {}
    for xor_key in range(128):
        s_xored = xor_encrypt(s, xor_key).lower()
        res_dict[xor_key] = evaluate(s_xored)
    return heapq.nsmallest(guess_cnt, res_dict, key=res_dict.get)
```

[`heapq`](https://docs.python.org/3/library/heapq.html) - implements a minimum heap. this allows for efficient finidng of the smallest elements.

an even faster way to do so, would be to implement [`quickselect`](https://en.wikipedia.org/wiki/Quickselect), which works similaraly to quicksort; but as `len(res_dict)` is very small, i think the built in libary should perform faster.


```python
from binascii import unhexlify
s_hex =  "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
xor_key1, xor_key2 = break_single_byte_xor(s_hex)
s = unhexlify(s_hex)
res = xor_encrypt(s, xor_key1)
res.decode()
```




    "Cooking MC's like a pound of bacon"



## challenge 4:  Detect single-character XOR

[<strong> description</strong>](https://cryptopals.com/sets/1/challenges/4): <br>
> One of the 60-character strings in [this file](https://cryptopals.com/static/challenge-data/4.txt) has been encrypted by single-character XOR. <br>
Find it. <br>
(Your code from #3 should help.)

<strong> plan of attack: </strong> <br>
1. read the lines from the file.
2. for every line: gather the `guess_cnt` most likely keys, and the resulting plaintext, just like in challenge 3.
3. pick the best-score `guess_cnt` plaintext amongst them all 


```python
from binascii import unhexlify
from heapq import nsmallest

read_file = lambda filepath: open(filepath).read().splitlines()

def chall4_sol(filepath, guess_cnt):
    file_lines = read_file(filepath)
    possible_words = []
    for line in file_lines:
        most_likely_keys = break_single_byte_xor(line, guess_cnt)
        for key in most_likely_keys:
            possible_words.append(xor_encrypt(
                unhexlify(line), key).strip())
    return heapq.nsmallest(guess_cnt, possible_words, key=evaluate)
```


```python
chall4_sol("input_files/4.txt", 3)[0].decode()
```




    'Now that the party is jumping'



## challenge 5: implement repeating key XOR 

[<strong> description</strong>](https://cryptopals.com/sets/1/challenges/4): <br>
> Here is the opening stanza of an important work of the English language: <br><br>
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal <br><br>
Encrypt it, under the key "ICE", using repeating-key XOR. <br><br>
In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on. <br><br>
It should come out to: <br><br>
*0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272*
*a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f*

luckily, we have the very powerfull `itertools` at our aid, which makes things quite simple. specifically its [`cycle`]("https://docs.python.org/3/library/itertools.html#itertools.cycle") method


```python
from itertools import cycle
from binascii import hexlify

def repeating_key_XOR(s, key):
    key_bytes = key.encode()
    s_bytes = s.encode()
    return bytearray([a^b for a,b in zip(s_bytes, cycle(key_bytes))])
```


```python
s = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
hexlify(repeating_key_XOR(s, "ICE"))
```




    b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'



## challenge 6: Break repeating-key XOR

[<strong> description:</strong>](https://cryptopals.com/sets/1/challenges/6) <br>
> It is officially on, now. <br><br>
This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6. <br><br>
There's a [file](https://cryptopals.com/static/challenge-data/6.txt) here. It's been base64'd after being encrypted with repeating-key XOR. <br><br>
Decrypt it.
"""

This was an intresting challenge. our <strong> plan of attack is </strong>

1. first we guess the keysize:
    1. we write a [`hamming_distance`](https://en.wikipedia.org/wiki/Hamming_distance) function - the hamming distance is the number of differing bits <strong>(NOTE: not letters, but bits)</strong> between two string, this can be easily achieved by $\oplus$ing the two strings, and counting how many bits are on. 
    2. for every keysize in range(min_keysize, max_keysize):
         1. split the ciphertext into blocks of size keysize each. then go through the text summing the hamming distance of every 2 adjacent blocks (so block1 with 2, block 3 with 4 etc...).<br> while summing, normalize diving by keysize. this is because as the length of the block increases, so does inevitably its hamming distance<br>
         2. normalize the entire sum, by the block count. this is because of we take for instance the string: 
         <i>"12345678"</i>. one way we may calcaulte its keysize is by doing for keysize=2: <br>
         <font size = 4.5> $\frac{`12`\oplus`34`}{2} + \frac{`56`\oplus`78`}{2} = \frac{`1234`\oplus`5678`}{2}$ </font> <br> while another can be for keysize=4:
         <font size = 4.5> $\frac{`1234`\oplus`5678`}{4}$ </font>, which is why we need to normalize by the block count. (which will result in both keysize 2 & 4 being divided equally by 8) <br>
         <strong> the normalized sum is the score. the lower it is - the better. </strong>
         3. pick the `guess_cnt` smallest-scored keysizes. those are our candidates.


```python
# step A
def hamming_dist(s1_bytes : bytes, s2_bytes : bytes):
    return sum(__get_differing_bits_between_bytes(b1, b2) for b1,
        b2 in zip(s1_bytes, s2_bytes))
def __get_differing_bits_between_bytes(byte1, byte2):
    num, cnt = byte1^byte2, 0
    for i in range(8):
        cnt += (num >> i) & 1
    return cnt
```


```python
# step B
from heapq import nsmallest

def get_keysize(ciphertext_bytes, guess_cnt=3):
    keysize_scores_dic = {}
    for keysize in range(MIN_XOR_KEYSIZE, MAX_XOR_KEYSIZE + 1):
        count = len(ciphertext_bytes)//keysize
        if count <= 1:
            continue
        keysize_score = get_keysize_score(ciphertext_bytes, keysize, count)
        keysize_scores_dic[keysize] = keysize_score
    return nsmallest(guess_cnt, keysize_scores_dic, key=keysize_scores_dic.get)

def get_keysize_score(ciphertext_bytes, keysize, count = 2):
    total_score = 0
    words = [ciphertext_bytes[keysize*i:keysize*(i+1)] for i in range(count)]
    for i in range(0, count-1, 2):
        total_score += hamming_dist(words[i], words[i+1])/(keysize)
    return total_score/(count//2)
```

### why this works?

consider two random bytes. the [expected value](https://en.wikipedia.org/wiki/Expected_value) of their hamming distance is:

<font size = 4.5> $\mathbb{E}[HammingDist(b1,b2)] = \sum_{X=0}^{8}\mathbb{P}(HammingDist(b1,b2)=X)\cdot X = \sum_{i=0}^{8} \frac{256\cdot \binom{8}{i}}{256^2}\cdot i = \sum_{i=0}^{8}\frac{\binom{8}{i}}{256}\cdot i = 4 $ </font>

we use a unified probablity space $\Omega$ where $P(\omega) = \frac{1}{|\Omega|}$. multiplying by $256$ is because of all the possible values for the first byte, and the $\binom{8}{i}$ is how many options there are for the second byte, depending on the hamming distance meaning how many bits are different from the first one. we divide by $256^2$ because $|\Omega| = 256^2$.


```python
from math import comb
sum(i*comb(8, i) for i in range(9))/256
```




    4.0



however, for two random alphanumeric letter, as the ones we would find in a plaintext, their values range between 48-122 (ascii table), which is significantly smaller than 0-255. this means the expected value of their hamming distance is going to be smaller:

<font size = 4.5> $b1,b2\in{AlphaNumerics} \implies 48 <= b1, b2 <= 122 \implies \mathbb{E}[HammingDist(b1,b2)] = \sum_{b1,b2\in{AlphaNumerics}}\mathbb{P}(b1,b2)\cdot HammingDist(b1,b2) = $ <br> $= \frac{1}{|\Omega|}\sum_{b1,b2\in{AlphaNumberics}}HammingDist(b1,b2) = 3.311  $ </font>

and this is for the entire 48-122 range, while in reality there are barely any non-letters in plaintext therefore making the expected hamming value even smaller.


```python
total = 0
for b1 in range(48, 123):
    for b2 in range(48, 123):
        total += __get_differing_bits_between_bytes(b1, b2)
total /= (122-48+1)**2
total
```




    3.3109333333333333



consider `ciphertext`. divide ciphertext into `blocks` for a given `keysize`.
- if keysize is correct: `blocks[i] = plaintext[keysize*i:keysize*(i+1)]` $\oplus$ `key`; `blocks[i+1] = plaintext[(i+1)*keysize:(i+2)*keysize]` $\oplus$ `key`. when we do `blocks[i]` $\oplus$ `blocks[i+1] = alphanumeric_hamming` <strong> the key cancels out as $\oplus$ is commutative</strong>, and we are left with plaintext hamming which has an expected value <= 3.3
- if keysize is incorrect: `blocks[i]` $\oplus$ `blocks[i+1] = random_bytes_hamming` as key won't cancel itself out, resulting in an expected value of 4.0.

hence, the correct keysize should have the best score (meaning smallest) after decet normalization

Now that we have our correct keysize its time to get back to the attack plan:

2. we then create tmp_blocks of size `keysize` out of the cipher, we fill the last block if necessary with 0s.
3. we create new blocks, where block[k] = [tmp_block[k] for tmp_block in tmp_blocks]
4. assuming we are correct about the keysize, every block in blocks was encrypted using a single byte xor. now this we already know how to solve, so we solve for every block.
5. we concatenate the results and we WIN :). this is a good time to use some neat pythoninc code as well:


```python
from binascii import hexlify
from itertools import zip_longest

MIN_XOR_KEYSIZE = 2
MAX_XOR_KEYSIZE = 30

def break_repeating_key_XOR(ciphertext_bytes, guess_cnt=3):
    possible_keys = []
    possible_keysizes = get_keysize(ciphertext_bytes, guess_cnt)
    for keysize in possible_keysizes:
        key = bytearray(__break_repeating_key_XOR_with_keysize(ciphertext_bytes, keysize)).decode()
        possible_keys.append(key)
    return possible_keys

def __break_repeating_key_XOR_with_keysize(ciphertext_bytes, keysize):
    res_arr = []
    blocks = handle_block_logic(ciphertext_bytes, keysize)
    for block in blocks:
        tmp = break_single_byte_xor(hexlify(bytearray(block)), 1)
        byte_key1 = tmp[0]
        res_arr.append(byte_key1)
    return res_arr

def handle_block_logic(ciphertext_bytes, keysize):
    # create the blocks of size keysize.
    blocks = __grouper(ciphertext_bytes, keysize, fillvalue=0)
    # the * unpacks the iterator returned by grouper, then zips the blocks together which is step (3)
    transformed_blocks = list(zip(*blocks))
    return transformed_blocks

"""taken directly from the itertools docs recipe section
(https://docs.python.org/3/library/itertools.html#itertools-recipes)"""
# this works because we are creating n references to the same iterator and not n iterators
def __grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n 
    return zip_longest(*args, fillvalue=fillvalue)
```


```python
from base64 import b64decode
get_ciphertext_from_file = lambda filename: b64decode(open(filename).read()) 
```


```python
guess_cnt = 1
filepath = "input_files/6.txt"

ciphertext_bytes = get_ciphertext_from_file(filepath)
possible_keys = break_repeating_key_XOR(ciphertext_bytes, guess_cnt)
for key in possible_keys:
    print(f"key: '{key}' | keysize: {len(key)}")
    res = repeating_key_XOR(ciphertext_bytes.decode(), key).decode()
    print(res)
```

    key: 'Terminator X: Bring the noise' | keysize: 29
    I'm back and I'm ringin' the bell 
    ...



```python

```
