#!/usr/bin/python3

# filenames with these extensions will be analyzed
pictures_extensions = [".jpg", ".jpeg", ".png", ".gif"] 
# chunk size in bytes used in MD5 and SHA1 functions
bsize = 512

# Hash sets in X-Ways format requires definition of hash type in first line e.g. MD5
# In software like Autopsy by (The Sleuth Kit) hash set starts with checksum.
# To prepare hash set in required format, uncomment proper hash set type:
hashset_type = "xways"
# hashset_type = "autopsy"


# this function is calculating MD5 for file
def md5_for_file(current_file):                                              
    from hashlib import md5
    hash_md5 = md5()
    with open(current_file, "rb") as f:
        data = f.read(bsize)
        while len(data) > 0:
            hash_md5.update(data)
            data = f.read(bsize)
    return hash_md5

# this function is calculating SHA1 for file
def sha1_for_file(current_file): 
    from hashlib import sha1
    hash_sha1 = sha1()
    with open(current_file, "rb") as f:
        data = f.read(bsize)
        while len(data) > 0:
            hash_sha1.update(data)
            data = f.read(bsize)
    return hash_sha1

def main():
    import sys, os
    import base64
    from sys import argv
    from datetime import datetime
    from tqdm import tqdm  
    argv = sys.argv[1:]
    # timestamp is required for creating unique reports filenames
    now = datetime.now().strftime("%Y-%m-%d  %H.%M.%S")
    
    if os.path.isdir(argv[0]):
        file_list = list()
        print(f"[+] Analysing directory \"{argv[0]}\"")
        for dir_path, dir_names, file_names in os.walk(argv[0]):
            for file in file_names:
                file_list.append(os.path.join(dir_path, file))
                
        if len(file_list) > 0:                                                      
            from nudenet import NudeDetector
            detector = NudeDetector()
            md5_set_nudenet = set()
            hits_nudenet=0
            nudenet_classes = ["EXPOSED_BREAST_F", "EXPOSED_ANUS", "EXPOSED_GENITALIA_F", "EXPOSED_GENITALIA_M", "EXPOSED_BUTTOCKS"]
            pbar = tqdm(file_list, desc="Progress")
            for file in pbar:
                extension = os.path.splitext(file)[1]
                if extension in pictures_extensions:
                    try:
                        current_picture = detector.detect(file, mode='fast')
                        for dict in current_picture:
                            if dict['label'] in nudenet_classes:
                                md5_set_nudenet.add(str(md5_for_file(file).hexdigest()))
                                hits_nudenet+=1
                                pbar.set_postfix(Hits=hits_nudenet)
                                break
                    except:
                        
                        print(f"[!] Error in '-nudenet' module, unable to analyze file: {file}")
                
            if hits_nudenet > 0:
                nudenet_file = "".join((argv[0]," -nudenet ",str(now),".hsh")).replace(":"," ").replace("/"," ").replace("\\"," ").lstrip().rstrip()
                f = open(nudenet_file, mode='w')                         
                if hashset_type == "xways":
                    f.write("MD5\n")
                for i in md5_set_nudenet:
                    f.write(i + "\n")
                f.close()
                print(f"[+] Potentially {hits_nudenet} hits has been found by '-nudenet' module")
                print(f"[+] Report saved in current working directory as \"{nudenet_file}\"")
        else:
            print(f"[x] Directory is empty, nothing to do in \"{argv[0]}\"")
if __name__ == '__main__':
	main()