import hashlib

def testPass(cryptPass, algo = "sha256"):
    #take first 2 chars as salt
    salt = cryptPass[0:2]
    dictFile = open('dictionary.txt', 'r')
    for word in dictFile.readlines():
        word = word.strip('\n')

        #hash candidate password
        if algo == "sha256":
            cryptWord = hashlib.sha256((salt + word).encode()).hexdigest()

        elif algo == "md5":
            cryptWord = hashlib.md5((salt + word).encode()).hexdigest()

        elif algo == "sha1":
            cryptWord = hashlib.sha1((salt + word).encode()).hexdigest()
            
        else:
            raise ValueError("Unsupported hashing algorithm")
        
        if cryptWord == cryptPass:
            print(f"[+] Found Password: {word}\n")
            return True
    print("[-] Password Not Found")
    return False


def main():
    try:
        with open(input("Input your txt file: "), 'r') as passFile:
            for line in passFile.readlines():
                if ':' in line:
                    user = line.split(':')[0]
                    cryptPass = line.split(':')[1].strip()
                    print(f"[+] Cracking Password for: {user}")
                    testPass(cryptPass, algo="sha256")

    except FileNotFoundError:
        print(f"[-] passwords.txt file not found!")
    
if __name__ == "__main__":
    main()
