from Crypto.Util import number 
import Crypto.Random.random as rand
import codecs

def generate_keys(e):
    while True:
        p = number.getPrime(rand.randint(1, 2048))
        q = number.getPrime(rand.randint(1, 2048))
        phi = (p-1) * (q-1)
        if e < phi and number.GCD(e, phi) == 1:
            break
    d = modular_inverse(e, phi)
    if not d:
        raise Exception('Multiplicative inverse not found')
    n = p * q
    return (n, e), d

# works when a and m are relatively prime
# therefore always works in our case, since e and phi are always relatively prime
def modular_inverse(a, m):
    m0 = m
    y = 0
    x = 1
    if (m == 1):
        return 0
    while (a > 1):
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        # Update x and y 
        y = x - q * y
        x = t
    # Make x positive 
    if (x < 0):
        x = x + m0
    return x

def encrypt_message(public_key, message):
    n = public_key[0]
    e = public_key[1]
    hex = codecs.encode(message.encode('utf8'), 'hex')
    num = int.from_bytes(hex, byteorder='big')
    cipher = (num ^ e) % n
    return cipher

def decrypt_message(public_key, private_key, cipher):
    n = public_key[0]
    num = (cipher ^ private_key) % n
    # bts = int.to
    # plaintext = bts.decode('utf8') 

def main():
    alice_public, alice_private = generate_keys(65537)
    cipher = encrypt_message(alice_public, 'who hee who ha ha ting tang walla walla bing bang')
    print(cipher)
    plaintext = decrypt_message(alice_public, alice_private, cipher)

if __name__ == '__main__':
    main()