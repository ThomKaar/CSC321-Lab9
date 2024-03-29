# This file is the python code to fulfill task2 for CSC321 Lab9
# We will be implementing Diffie Hellman with a few tweaks
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import Crypto.Random.random as rand 
from Crypto.Util.number import long_to_bytes
# execute key exchange
def main():
   p = 37
   g = 1
   # g = 1
   # g = p - 1

   
   # A = g**(randomInt) % p
   # a = randomInt
   A, a = pickAB(p, g)
   
   # B = g**(randomInt) % p
   # b = randomInt   
   B, b = pickAB(p, g)

   # Now here comes the big bad Mallory... dun dun duuuuun
   MA, ma = pickAB(p, g)
   MB, mb = pickAB(p, g)
   
   s_input_MA = sym_input(A, ma, p)
   s_input_MB = sym_input(B, mb, p)
   s_input_Alice = sym_input(MA, a, p)
   s_input_Bob = sym_input(MB, b, p)
   
   
   sym_key_Alice = generate_key(SHA256.new(), long_to_bytes(s_input_Alice))
   sym_key_MAlice = generate_key(SHA256.new(), long_to_bytes(s_input_MA))
 
   sym_key_Bob = generate_key(SHA256.new(), long_to_bytes(s_input_Bob))
   sym_key_MBob = generate_key(SHA256.new(), long_to_bytes(s_input_MB))


   # We now have symmetric keys
   
   alice_iv, alice_cipher = buildCipher("Hi Bob!", sym_key_Alice)
   bob_iv, bob_cipher = buildCipher("Hi Alice!", sym_key_Bob)
   
      # Now let's use Mallory's evil keys
   alice_decrypted = aes_decrypt(alice_cipher, sym_key_MBob, alice_iv)
   bob_decrypted = aes_decrypt(bob_cipher, sym_key_MAlice, bob_iv)
   print("Decrypting with Mallory's evil keys")
   print('Alice Hi Decrypted: {}'.format(alice_decrypted))
   print('Bob Hi Decrypted: {}'.format(bob_decrypted))
   
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
   iv = rand_file.read(16)
   cipher = aes_encrypt(message, key, iv)
   return iv, cipher

# AES encrypt the message with the given key and IV
def aes_encrypt(message, key, iv):
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad_aes_message(message)
    return encryptor.encrypt(padded_message)
        
def aes_decrypt(message, key, iv):
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    return decryptor.decrypt(message)

def pad_aes_message(message):
    acc = ''
    i = 0
    j = 16
    while len(message[i:j]) == 16:
        acc += message[i:j]
        i += 16
        j += 16
    acc += pkcs7(message[i:j])
    return acc
        
def pkcs7(plaintext):
   if len(plaintext) == 16:
      pad_len = 16
   else:
      pad_len = 16 - len(plaintext)
   # pad_char = pad_len.to_bytes(1, byteorder='big')
   pad_char = ';'
   for i in range(pad_len):
      plaintext += pad_char
   return plaintext

# Given a p and g value choose a random int between 1 and p-2 
# and return (g**random_int) % p and random_int
def pickABbytes(p, g):
   ab = rand.randint(1, int.from_bytes(p, "big")-2)
   return pow(int.from_bytes(g, "big"),ab, int.from_bytes(p, "big")), ab   



if __name__ == '__main__':
   main()
