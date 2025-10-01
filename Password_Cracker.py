import os
import sys
import multiprocessing
from passlib.hash import sha512_crypt, md5_crypt, sha256_crypt, des_crypt

# Map hash prefix -> passlib handler
HASH_HANDLERS = {
    "1": md5_crypt,
    "5": sha256_crypt,
    "6": sha512_crypt,
}

def identify_handler(crypt_pass: str):
    """
    Identify which Passlib handler to use based on the hash format.
    Example: $6$salt$hash -> SHA-512
    """
    if crypt_pass.startswith("$"):
        parts = crypt_pass.split("$")
        if len(parts) > 2 and parts[1] in HASH_HANDLERS:
            return HASH_HANDLERS[parts[1]]
    # fallback to old DES crypt
    return des_crypt

def try_word(word, crypt_pass, handler):
    """
    Try a single word against a hashed password using the right handler.
    """
    word = word.strip()
    try:
        if handler.verify(word, crypt_pass):
            return word
    except Exception:
        pass
    return None

def crack_password(crypt_pass, dict_path):
    """
    Crack one password using multiprocessing with dictionary attack.
    """
    handler = identify_handler(crypt_pass)

    # Read dictionary words once
    try:
        with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
            words = f.read().splitlines()
    except Exception as e:
        print(f"[-] Error reading dictionary: {e}")
        return None

    # Use multiprocessing Pool
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.starmap(
            try_word,
            [(word, crypt_pass, handler) for word in words]
        )

    # Check if any succeeded
    for res in results:
        if res:
            return res
    return None

def main():
    pass_path = input("Enter the path to the password file: ").strip()
    dict_path = input("Enter the path to the dictionary file: ").strip()

    if not os.path.isfile(pass_path):
        print("[-] Password file not found.")
        return
    if not os.path.isfile(dict_path):
        print("[-] Dictionary file not found.")
        return

    with open(pass_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if ":" in line:
                user, crypt_pass = line.strip().split(":", 1)
                print(f"[*] Cracking password for: {user}")
                password = crack_password(crypt_pass.strip(), dict_path)
                if password:
                    print(f"[+] Found Password for {user}: {password}")
                else:
                    print(f"[-] No password found for {user}")

if __name__ == "__main__":
    main()
