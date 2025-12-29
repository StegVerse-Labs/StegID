from stegid.receipts import generate_keypair

if __name__ == "__main__":
    priv_b64, pub_b64 = generate_keypair()
    print("STEGID_ED25519_PRIVATE_B64 (store as GitHub Secret):")
    print(priv_b64)
    print()
    print("STEGID_ED25519_PUBLIC_B64 (store in repo, or as public):")
    print(pub_b64)
