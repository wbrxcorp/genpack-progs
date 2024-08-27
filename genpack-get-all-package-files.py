#!/usr/bin/python3

import os,re,argparse,sys

def print_all_files_of_all_packages(pkgs):
    for pkg in pkgs:
        if pkg[0] == '@': continue
        contents_file = os.path.join("/var/db/pkg" , pkg, "CONTENTS")
        if not os.path.isfile(contents_file): continue
        #else
        with open(contents_file) as f:
            while line := f.readline():
                line = re.sub(r'#.*$', "", line).strip()
                if line == "": continue
                file_to_append = None
                if line.startswith("obj "): 
                    file_to_append = re.sub(r' [0-9a-f]+ [0-9]+$', "", line[4:])
                    if not os.path.exists(file_to_append):
                        print(f"# file {file_to_append} does not exist", file=sys.stderr)
                        file_to_append = None
                elif line.startswith("sym "):
                    file_to_append = re.sub(r' -> .+$', "", line[4:])
                    if not os.path.islink(file_to_append):
                        print(f"# link {file_to_append} does not exist", file=sys.stderr)
                        file_to_append = None
                if file_to_append is not None: print(file_to_append)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get all files of all packages')
    parser.add_argument('pkgs', type=str, nargs='+', help='List of packages')
    args = parser.parse_args()
    print_all_files_of_all_packages(args.pkgs)