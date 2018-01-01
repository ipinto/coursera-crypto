# Many Time Pad

## Exercise

Let us see what goes wrong when a stream cipher key is used more than once. Below are eleven hex-encoded ciphertexts that are the result of encrypting eleven plaintexts with a stream cipher, all with the same stream cipher key. Your goal is to decrypt the last ciphertext, and submit the secret message within it as solution.

**Hint**: XOR the ciphertexts together, and consider what happens when a space is XORed with a character in [a-zA-Z].

**ciphertext #1:**
_315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e_

**ciphertext #2:**
_234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f_

**ciphertext #3:**
_32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb_

**ciphertext #4:**
_32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa_

**ciphertext #5:**
_3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070_

**ciphertext #6:**
_32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4_

**ciphertext #7:**
_32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce_

**ciphertext #8:**
_315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3_

**ciphertext #9:**
_271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027_

**ciphertext #10:**
_466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83_

**target ciphertext (decrypt this one):**
_32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904_

For completeness, here is the python script used to generate the ciphertexts.

(it doesn't matter if you can't read this)

```python
import sys

MSGS = ( ---  11 secret messages  --- )

def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
       return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
       return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def random(size=16):
    return open("/dev/urandom").read(size)

def encrypt(key, msg):
    c = strxor(key, msg)
    print
    print c.encode('hex')
    return c

def main():
    key = random(1024)
    ciphertexts = [encrypt(key, msg) for msg in MSGS]
```

## Solution

I created a "very manual" script which helps crib-dragging.

You should execute the script passing an argument with a
string that may match any part of the compared messages
(the target and the longest ciphertexts).

It will display all the possible matching options for that
string in that position. If it sounds good, you can add it
to the solutions lists.

We don't know if the discovered strings are part of the target
or part of the message. We should keep discovering more words
and move them to the correct one. Be aware that the largest
ciphertexts should not be complete discovered.

### Example

```
➜  week1 git:(week-1) ✗ python run.py " the "
Crib: " the "
[0] -> th76<-
[1] -> t:se<-
[3] ->rb-g <-
[4] ->61je <-
[5] ->evhet<-
[6] ->"th1t<-
[9] ->t ros<-
[10] ->tnb6'<-
[13] ->sspr <-
[15] ->8ch6i<-
[35] -> hrre<-
[40] ->5q)ri<-
[47] ->)i36n<-
[51] ->never<-
[52] ->1jh7G<-
[56] ->Gnmer<-
[57] ->:qh7:<-
[60] ->rnmen<-
[63] -> :w -<-
[64] ->nk-ho<-
[66] ->ey'(:<-
[68] ->o9rd <-
[69] ->mnie <-
[70] ->:uhe6<-
[73] -> brq:<-
[77] ->:1'm,<-
Possible target: ...................................................................................
Possible message: ..........................................................................................................................................................................................
Possible key: 1c7f258794909590d32e3b69863ec85f67e4c03ff76be351e6342bc7d674824b20be7c9444a2f60b55df633dc8de862d9b61f0b059690391d6b35f9b55f3c13c3d18e5abe296dd1f71657ccd2fff40b17cd72a
Secret target message --> ...................................................................................
```

We can see that *never* word appears in position 51, so we add to the script
`resolve(51, "never", " the ")` in the `add_solutions()` method.

If we executed again looking for other text:

```
➜  week1 git:(week-1) ✗ python run.py " message "
Crib: " message "
[1] -> m7e6cget<-
[7] -> m1'ik4b8<-
[10] ->two types<-
[11] ->:g6tkvg6i<-
[22] -> Ytfi.ud(<-
[37] ->:z fv p,1<-
[67] ->-"(irags:<-
[74] ->6wqi6.oi7<-
Possible target: ...................................................never...........................
Possible message: ................................................... the ..................................................................................................................................
Possible key: 1c7f258794909590d32e3b69863ec85f67e4c03ff76be351e6342bc7d674824b20be7c9444a2f60b55df633dc8de862d9b61f0f0123148cdd6b35f9b55f3c13c3d18e5abe296dd1f71657ccd2fff40b17cd72a
Secret target message --> ...................................................never...........................
```

We can see that that the position 10 string has sense, but we also
see that the last discovered words are now placed in the messages.

If we continue guessing, we will see that we are getting not ordered
phrases:

```
Possible target: Thereecret message is: When using a .......cipher, never use the key...............
Possible message: The s are two types of cyptography: .......t allows the Government t......................................................................................................................
Possible key: 66396edbdfdbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a44a2f60b55df63708f80c066c763fef0123148cdd8e802d05ba98777335daefce296dd1f71657ccd2fff40b17cd72a
Secret target message --> Thereecret message is: When using a .......cipher, never use the key...............
```

As soon as we notice this, we should reorder the words (changing the parameters
order in `resolve` method).

Once we discover all the content of the target, we can also get the correct key
for that length, and the plaintext of the other ciphertexts:

```
Possible target: The secret message is: When using a stream cipher, never use the key more than once
Possible message: There are two types of cyptography: one that allows the Government to use brute for*******************************************************************************************************
Possible key: 66396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a19f8aa401a9c6d708f80c066c763fef0123148cdd8e802d05ba98777335daefcecd59c433a6b268b60bf4ef03c9a61
Secret target message --> The secret message is: When using a stream cipher, never use the key more than once

PLAIN TEXTS
===========
- We can factor the number 15 with quantum computers. We can also factor the number 1
- Euler would probably enjoy that now his theorem becomes a corner stone of crypto -
- The nice thing about Keeyloq is now we cryptographers can drive a lot of fancy cars
- The ciphertext produced by a weak encryption algorithm looks as good as ciphertext
- You don't want to buy a set of car keys from a guy who specializes in stealing cars
- There are two types of cryptography - that which will keep secrets safe from your l
- There are two types of cyptography: one that allows the Government to use brute for
- We can see the point where the chip is unhappy if a wrong bit is sent and consumes
- A (private-key)  encryption scheme states 3 algorithms, namely a procedure for gene
-  The Concise OxfordDictionary (2006) deﬁnes crypto as the art of  writing o r sol
- The secret message is: When using a stream cipher, never use the key more than once
```
