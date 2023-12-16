#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: shimarin
# Created: 2023-12-16

import os,re,time,argparse,urllib.request,tarfile

_v = r"(\d+)((\.\d+)*)([a-z]?)((_(pre|p|beta|alpha|rc)\d*)*)"
_rev = r"\d+"
_pv_re = re.compile(r"^"
    "(?P<pn>"
    + r"[\w+][\w+-]*?"
    + "(?P<pn_inval>-"
    + _v + "(-r(" + _rev + "))?"
    + ")?)"
    + "-(?P<ver>"
    + _v
    + ")(-r(?P<rev>"
    + _rev
    + "))?"
    + r"$", re.VERBOSE | re.UNICODE)

def pkgsplit(mypkg):
    """
    @param mypkg: pv
    @return:
    1. None if input is invalid.
    2. (pn, ver, rev) if input is pv
    """
    m = _pv_re.match(mypkg)
    if m is None or m.group("pn_inval") is not None: return None
    #else
    rev = m.group("rev")

    return (m.group("pn"), m.group("ver"), "r" + ("0" if rev is None else rev))

def split_into_category_and_name_and_version(line):
    if '/' not in line: return None
    category,mypkg = line.split('/', 1)
    pn_ver_rev = pkgsplit(mypkg)
    if not pn_ver_rev: return None
    #else
    pn, ver, rev = pn_ver_rev
    return (category,pn, ver + ("" if rev == "r0" else "-" + rev))

def download_file(url, save_to):
    # if file is already downloaded and fresh enough, do nothing
    if os.path.isfile(save_to):
        download_time = os.path.getmtime(save_to)
        # if the file is downloaded within 1 hour, do nothing
        if time.time() - download_time < 3600: return False
    #else
    urllib.request.urlretrieve(url, save_to)
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get latest monero|p2pool download url')
    parser.add_argument('packages_file', type=str, nargs='?',
                        default='/.genpack/packages', help='Packages file')
    parser.add_argument("--report-file", type=str, default=None, help="Report file")
    args = parser.parse_args()

    RUNTIME_DIR = os.getenv("XDG_RUNTIME_DIR")
    if not RUNTIME_DIR:
        RUNTIME_DIR = "/run"

    PORTAGE_LATEST_TAR_XZ = os.path.join(RUNTIME_DIR, "portage-latest-for-check-outdated-packages.tar.xz")

    print("Downloading portage-latest.tar.xz...")
    if download_file("http://ftp.iij.ad.jp/pub/linux/gentoo/snapshots/portage-latest.tar.xz", PORTAGE_LATEST_TAR_XZ):
        print("Downloaded.")
    else:
        print("Already downloaded.")

    print("Getting file list from portage-latest.tar.xz...")
    with tarfile.open(PORTAGE_LATEST_TAR_XZ, "r:xz") as tar:
        file_list = tar.getnames()

    ebuilds = set()
    for file in file_list:
        if not file.startswith("portage/"): continue
        file = file[len("portage/"):]
        if file.endswith(".ebuild"):
            ebuilds.add(file)
            #print("Found: %s" % file)

    outdated = set()
    if args.report_file and os.path.exists(args.report_file):
        print("Removing old report file: %s" % args.report_file)
        os.remove(args.report_file)

    packages = []

    with open(args.packages_file, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or line == "": continue
            #else
            packages.append(line)
    
    # sort packages by alphabetical order
    packages.sort()

    ignoreable_categories = ["app-eselect", "acct-group", "acct-user", "virtual", "media-fonts", "x11-themes"]
    ignoreable_packages = ["app-admin/eselect", "sys-libs/timezone-data"]

    for package in packages:
        category_and_name_and_version = split_into_category_and_name_and_version(package)
        if not category_and_name_and_version:
            print("Invalid line: %s" % package)
            continue
        #else
        category,name,version = category_and_name_and_version
        if category in ignoreable_categories or ("%s/%s" % (category, name)) in ignoreable_packages: continue
        ebuild_name = "%s/%s/%s-%s.ebuild" % (category,name,name,version)
        #print(ebuild_name)
        if ebuild_name not in ebuilds:
            outdated.add(package)
            print("Outdated: %s" % package)
            if args.report_file:
                with open(args.report_file, "a") as report_file:
                    report_file.write("Outdated: %s\n" % package)

    if len(outdated) > 0:
        print("%s outdated package(s) found." % len(outdated))
        exit(1)
    #else
    print("No outdated packages found.")
