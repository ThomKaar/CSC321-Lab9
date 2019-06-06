# This file is an implementation of a Diffie Hellmen key exchange with using a 
# p value of 37 and a g value of 5 
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import Crypto.Random.random as rand 

# execute key exchange
def main():
   p = 37
   g = 5
   # A = g**(randomInt) % p
   # a = randomInt
   A, a = pickAB(p, g)
   
   # B = g**(randomInt) % p
   # b = randomInt   
   B, b = pickAB(p, g)

   s_input_Alice = sym_input(B, a, p)
   s_input_Bob = sym_input(A, b, p)
   hash = SHA256.new()
   sym_key_Alice = generate_key(hash, bytes(s_input_Alice))
   sym_key_Bob = generate_key(hash, bytes(s_input_Bob)) 

   # We now have symmetric keys
   
   alice_cipher = buildCipher("Hi Bob!", sym_key_Alice)
   bob_cipher = buildCipher("Hi Alice!", sym_key_Alice)

# Given a p and g value choose a random int between 1 and p-2 
# and return (g**random_int) % p and random_int
def pickAB(p, g):
   ab = rand.randint(1, p-2)
   return pow(g,ab, p), ab   

# Given A or B and a or b return (A**b) % p or (B**b) % p 
def sym_input(AorB, aorb, p):
   return pow(AorB, aorb, p)

# Given a sha256 hash and a int as bytes return the hashed int
def generate_key(hash, s_input):
   hash.update(s_input)
   return hash.digest()[:32]

# Given a message and a key that is 16 bytes long, build an AES-Cipher in CBC mode
def buildCipher(message, key):
   rand_file = Random.new()
   aes_obj = AES.new(key, AES.MODE_CBC, rand_file.read(16))
   cipher = ""
   i = 0
   
   return cipher

if __name__ == '__main__':
   main()
