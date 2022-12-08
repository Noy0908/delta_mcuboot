import os
import sys
from shutil import copyfile
from sys import exit

paths = "../binaries/signed_images"
sign_patch = "../binaries/patches/signed_patch.bin"
patch_path = "../binaries/patches/patch"
source_path = ''
#command = "detools create_patch --compression heatshrink binaries/signed_images/source.bin binaries/signed_images/target.bin binaries/patches/patch1.bin"
command = "detools create_patch --compression heatshrink "
source_version = ''
target_version = ''

def padded_hex(s,p):
    return '0x' + s[2:].zfill(p)

def create_patch_file(path):
    global command
    global patch_path
    global source_path
    global source_version
    global target_version
    source_count = 0
    target_count = 0.

    try:
        files = os.listdir(path)
        for file_name in files:
            #print("file_name="+file_name)
            if "source_" in file_name:
                source_count += 1
            elif "target_" in file_name:
                target_count += 1
    except:
        print("file path : [\"%s\"] error!\r\n" %(path))
        os.system("pause")
    else:      
        if(source_count != 1):
            print("Multiple source files:%d!!!\r\n" %source_count)
            os.system("pause")
        if(target_count != 1):
            print("Multiple target files:%d!!!\r\n" %target_count)
            os.system("pause")

        for file_name in files:
            if "source_" in file_name:
                source_path = os.path.normpath(os.path.join(path, file_name))
                source_version = file_name.split("_")[1].split(".bin")[0]
                # print("source file:%s  source_version:%s  source_path:%s"  %(file_name,source_version,source_path))
            elif "target_" in file_name:
                target_path = os.path.normpath(os.path.join(path, file_name))
                target_version = file_name.split("_")[1].split(".bin")[0]
                # print("target file:%s  target_version:%s  target_path:%s"  %(file_name,target_version,target_path))

        patch_path += "_from_" + source_version + "_to_" + target_version + ".bin"
        command += source_path + ' ' + target_path + ' ' + patch_path
        # print(command)
        try:
            os.system(command)
        except:
            print("Please install detools first. [\"pip3 install --user detools\"]\r\n")
            os.system("pause")



def sign_patch_file(sign_path):
    # print("source_path:%s" %source_path)
    size=os.stat(patch_path).st_size 
    f=open(patch_path,'r+b')
    contents = f.read()
    f.seek(0)
    f.write('NEWP'.encode()) 
    f.write(size.to_bytes(4,byteorder='little'))
    # write source hash value to patch file
    with open(source_path,"rb") as file_obj:
        file_obj.seek(12)
        value = file_obj.read(4)
        offset = int.from_bytes(value,byteorder='little')
        print("file_size = 0X%08x\n" %(offset))
        file_obj.seek(offset + 0x200 + 0x08)
        source_hash = file_obj.read(0x20)
        #print(source_hash)
        f.write(source_hash)
    # write file contents to new file
    f.write(contents)

    # excute signature command 
    try:
        with open(sign_path,encoding='utf-8') as file_obj:
            text = file_obj.read()
            sign_command = text.strip('\r\n') + ' ' + patch_path + ' ' + patch_path.replace("patch_from","signed_patch_from")
            # print(sign_command)
            os.system(sign_command)
    except:
        print("Please check your imgtool command: [\"%s\"]!!!\r\n" %sign_command)
        os.system("pause")
    else:
        # copy and rename the signed patch file , which will be used by make flash-patch command
        copyfile(patch_path.replace("patch_from","signed_patch_from"), sign_patch)



    print("\nFile copy done!\n")

if __name__ == "__main__":
    create_patch_file(paths)
    sign_patch_file("signature.py")
    os.system("pause")