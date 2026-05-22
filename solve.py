#!/usr/bin/env python3
"""
Cipher reconstruction and solver from bytecode analysis
Liga CTF - codec-auth challenge
"""

def _k3y_d3r1v(seed, rounds):
    """Key derivation function"""
    _p0 = bytearray((12, 6, 8, 7, 14, 7, 5, 2, 15, 14, 5, 12, 4, 4, 1, 2))
    _p1 = bytearray((10, 3, 7, 13, 14, 9, 2, 11, 4, 15, 6, 1, 12, 8, 5, 0))
    _p2 = tuple(a ^ b for a, b in zip(_p0, _p1))
    
    # Pad seed to 8 bytes
    _raw = seed.encode() + bytes(8)
    _raw = _raw[:8]
    
    _acc = bytearray(_raw)
    
    for _r in range(rounds):
        for _i in range(8):
            _acc[_i] = (_acc[_i] ^ _p2[(_r + _i) % 16]) ^ (_r & 255) & 255
    
    return bytes(_acc)


def _r0und_k3y(k, rc):
    """Round key generation function"""
    _p0 = bytearray((12, 6, 8, 7, 14, 7, 5, 2, 15, 14, 5, 12, 4, 4, 1, 2))
    _p1 = bytearray((10, 3, 7, 13, 14, 9, 2, 11, 4, 15, 6, 1, 12, 8, 5, 0))
    _p2 = tuple(a ^ b for a, b in zip(_p0, _p1))
    
    # Pad key to 10 bytes
    _raw = k + bytes(10)
    _raw = _raw[:10]
    
    K = int.from_bytes(_raw, 'big')
    
    # Extract top 4 bits at position 76
    top4 = (K >> 76) & 15
    
    # Substitution using permutation table
    K = (K & -1133367955888714851287041) | (_p2[top4] << 76)
    
    # Rotate bits
    K = ((K << 8) | (K >> 72)) & 1208925819614629174706175
    
    # XOR with round constant
    K ^= ((rc + 1) << 15)
    
    return K.to_bytes(10, 'big')


def _c1ph_rnd(blk, k10):
    """Main cipher round function"""
    _b0 = bytearray((12, 6, 8, 7, 14, 7, 5, 2, 15, 14, 5, 12, 4, 4, 1, 2))
    _b1 = bytearray((10, 3, 7, 13, 14, 9, 2, 11, 4, 15, 6, 1, 12, 8, 5, 0))
    _b2 = tuple(a ^ b for a, b in zip(_b0, _b1))
    
    # Convert block to integer
    b = int.from_bytes(blk, 'big')
    
    # Initial state extraction
    s = [(48 - i * 16) >> 9 & 65535 for i in range(4)]
    
    # Convert key to integer
    K = int.from_bytes(k10, 'big')
    
    rks = []
    _jx = 0
    
    # Generate round keys
    for rc in range(25):
        rks.append([(64 - i * 16) >> 9 & 65535 for i in range(4)])
        
        # Extract top 4 bits
        top4 = (K >> 76) & 15
        
        # Substitution
        K = (K & -1133367955888714851287041) | (_b2[top4] << 76)
        
        # Rotation
        K = ((K << 8) | (K >> 72)) & 1208925819614629174706175
        
        # XOR with round constant
        K ^= ((rc + 1) << 15)
        
        # Generate round key
        _jv = rc * rc + rc >> 1
        if _jv < 0:
            s = [0, 0, 0, 0]
    
    # Main cipher rounds
    for r in range(25):
        # Add round key
        for i in range(4):
            s[i] ^= rks[r][i]
        
        # Substitution and permutation
        ns = [0, 0, 0, 0]
        
        for c in range(16):
            # Build nibble from state bits
            n = (
                ((s[0] >> c) & 1) |
                (((s[1] >> c) & 1) << 1) |
                (((s[2] >> c) & 1) << 2) |
                (((s[3] >> c) & 1) << 3)
            )
            
            # S-box lookup
            sv = _b2[n]
            
            # Check for self-XOR property
            if (sv * sv ^ sv) & 255 == 255:
                sv ^= sv
            
            # Distribute S-box output back to state
            for row in range(4):
                ns[row] |= ((sv >> row) & 1) << c
        
        s = ns
        
        # Accumulate in _jx
        _jx ^= s[0] ^ r
        
        # Row rotations
        s[1] = ((s[1] << 1) | (s[1] >> 15)) & 65535
        s[2] = ((s[2] << 6) | (s[2] >> 10)) & 65535
        s[3] = ((s[3] << 13) | (s[3] >> 3)) & 65535
    
    # Convert state back to output
    out = 0
    for i in range(4):
        out |= s[i] << (48 - i * 16)
    
    return out.to_bytes(8, 'big')


def encrypt(plaintext, key):
    """Encrypt plaintext using the cipher"""
    if len(plaintext) != 8:
        raise ValueError("Plaintext must be 8 bytes")
    
    if len(key) != 10:
        raise ValueError("Key must be 10 bytes")
    
    return _c1ph_rnd(plaintext, key)


def decrypt(ciphertext, key):
    """
    Decrypt ciphertext - requires inverse cipher implementation
    For this CTF, we may need to brute force or analyze the cipher structure
    """
    # This would require implementing the inverse cipher
    # For now, we'll focus on encryption analysis
    raise NotImplementedError("Decryption requires inverse cipher analysis")


def crack_cipher(ciphertext, known_plaintext=None):
    """
    Attempt to crack the cipher given ciphertext and optional known plaintext
    """
    if known_plaintext:
        # With known plaintext, we can attempt to recover the key
        # This is a meet-in-the-middle or differential attack approach
        pass
    
    # Brute force key search (if keyspace is small)
    pass


def main():
    """Main solver function"""
    import sys
    
    # Example usage
    print("[*] Codec-Auth Cipher Solver")
    print("[*] ========================\n")
    
    # Test vectors (to be filled in from challenge)
    test_key = b"testkey123"  # 10 bytes
    test_plaintext = b"testdata"  # 8 bytes
    
    print(f"[+] Key: {test_key.hex()}")
    print(f"[+] Plaintext: {test_plaintext.hex()}")
    
    # Encrypt
    ciphertext = encrypt(test_plaintext, test_key)
    print(f"[+] Ciphertext: {ciphertext.hex()}\n")
    
    # Try key derivation
    derived_key = _k3y_d3r1v("password", 10)
    print(f"[+] Derived Key: {derived_key.hex()}")
    
    # Try round key generation
    round_key = _r0und_k3y(test_key, 0)
    print(f"[+] Round Key 0: {round_key.hex()}\n")
    
    # If you have a ciphertext file to crack
    if len(sys.argv) > 1:
        ciphertext_file = sys.argv[1]
        try:
            with open(ciphertext_file, 'rb') as f:
                ct = f.read()
            print(f"[*] Read ciphertext from {ciphertext_file}: {ct.hex()}")
            # Add your cracking logic here
        except FileNotFoundError:
            print(f"[-] File not found: {ciphertext_file}")
    
    print("\n[*] Solver complete")


if __name__ == "__main__":
    main()
