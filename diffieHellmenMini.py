# This file is an implementation of a Diffie Hellmen key exchange with using a 
# p value of 37 and a g value of 5 
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import Crypto.Random.random as rand 
from math import pow

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
   print("Alice is: ", s_input_Alice)
   print("  Bob is: ", s_input_Bob)
   hash = SHA256.new()
   sym_key_Alice = generate_key(hash, str(s_input_Alice).encode('utf-8'))
   sym_key_Bob = generate_key(hash, str(s_input_Bob).encode('utf-8')) 
   print(sym_key_Alice)
   print(sym_key_Bob) 

def pickAB(p, g):
   ab = rand.randint(1, p-2)
   return pow(g,ab) % p, ab   

def sym_input(AorB, aorb, p):
   return pow(AorB, aorb) % p

def generate_key(hash, s_input):
   hash.update(s_input)
   return hash.digest()

if __name__ == '__main__':
   main()
