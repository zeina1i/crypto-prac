# What is rsa
Rsa is an asymetric encryption tool. You can encrypt a message with a public key and decrypt it by private key.
# why is it hard to break?
Because it is based on two big numbers (p and q) where these numbers are prime numbers.
```
N = p * q
```
two things togeather make it hard:
1-prime numbers, because this guarantees the p and q are unique and the attacker cant come up with other factors.
2-the size of numbers, which are big and makes it hard to bruteforce .2048-bit numbers,

# how are the keys generated?
```
n, φ(n), e, d.

1-choose p and q
2-n = p * q
3-compute φ(n)
φ(n) means How many numbers between 1 and n share no common factors with n
it would be:
φ(n) = (p-1)(q-1) => this is euler, we use this which is proved before 
4- choose e:
e should satisfy two conditions:
 1. 1 < e < φ(n)                                                                                                                                                               
 2. gcd(e, φ(n)) = 1 — meaning e and φ(n) share no common factors  
5-compute d
  e × d ≡ 1 (mod φ(n))
6 -  result: public key is (e, n), private key is (d, n)
 ```

# encrypt and decrypt
the user uses the public key to encrypt, and the server uses the private key to decrypt
```
encrypt: c = m^e mod n                                                                                                                                                        
decrypt: m = c^d mod n
```
# why does decryption work?
because e and d are inverse of each other in world of  φ(n)
# the attackers has
```
 - n — the modulus (public)                                                                                                                                                    
  - e — the public exponent (public)                                                                                                                                            
  - c — the encrypted message (public)
```