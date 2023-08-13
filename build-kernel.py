#!/usr/bin/python
import os,subprocess,tarfile,re,glob,argparse,logging

GENERATED_KERNEL_CONFIG="/etc/kernels/kernel-config"

def is_kernel_built():
    kernel_release = get_kernel_release()
    if kernel_release is None: 
        return False

    kernel_files = [
        "/usr/src/linux/Module.symvers",
        "/usr/src/linux/scripts/module.lds",
        "/boot/kernel",
        "/boot/vmlinuz-%s" % kernel_release,
        os.path.join("/lib/modules", kernel_release, "modules.dep")
    ]
    for f in kernel_files:
        if not os.path.isfile(f): 
            logging.debug("Kernel file %s not found" % f)
            return False
    #else
    return True

def get_kernel_id():
    return os.readlink("/usr/src/linux")

def get_kernel_release() -> str:
    try:
        return subprocess.check_output(["make", "kernelrelease"],cwd="/usr/src/linux",encoding="utf-8", text=True).strip()
    except subprocess.CalledProcessError as e:
        logging.debug("make kernelrelease failed")
        return None
    except FileNotFoundError as e:
        logging.debug("Kernel source not found")
        return None

def build_kernel(config,menuconfig=False):
    genkernel_cmdline = ["genkernel", "--symlink", "--no-mountboot", "--no-bootloader",
        "--kernel-config=%s" % config, 
        "--kernel-config-filename=%s" % os.path.basename(GENERATED_KERNEL_CONFIG), 
        "--kernel-localversion=UNSET", "--no-keymap"]
    if menuconfig: genkernel_cmdline.append("--menuconfig")
    if os.path.exists(GENERATED_KERNEL_CONFIG): os.unlink(GENERATED_KERNEL_CONFIG)
    genkernel_cmdline.append("kernel")
    subprocess.check_call(genkernel_cmdline)

    # update kernel config
    with open(config, "a") as f:
        f.truncate(0)
        with open(GENERATED_KERNEL_CONFIG) as f2:
            for line in f2:
                if line[0] != '#': f.write(line)

    # cleanup
    for old in glob.glob("/boot/*.old"):
        os.unlink(old)
    subprocess.check_call(["eclean-kernel", "-n", "1"])

def generate_kernel_cache(output, include_modules = True):
    kernel_id = get_kernel_id()
    kernel_release = get_kernel_release()
    if kernel_release is None:
        raise Exception("Kernel has never been built")
    files = [
        "/boot/kernel",
        "/boot/vmlinuz-%s" % kernel_release,
        "/usr/src/linux",
        "/usr/src/%s/.config" % kernel_id,
        "/usr/src/%s/Module.symvers" % kernel_id,
        "/usr/src/%s/scripts/module.lds" % kernel_id,
    ]
    if include_modules:
        files.append(os.path.join("/lib/modules" , kernel_release))

    os.makedirs(os.path.dirname(output), exist_ok=True)

    with tarfile.open(output + ".tmp", "w:gz") as tar:
        for f in files:
            tar.add(f, arcname=re.sub(r"^/+", "", f))
    os.rename(output + ".tmp", output)

def get_kernel_id_from_kernel_cache(archive_path):
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name == "usr/src/linux":
                return member.linkname
    #else
    logging.warning("Could not find kernel id from kernel cache")
    return None

def main(kernelpkg="gentoo-sources",config="/etc/kernels/kernel-config", menuconfig=False, cache_file_name="/var/cache/build-kernel/kernel-cache.tar.gz"):
    # emerge kernel and requirements
    subprocess.check_call(["emerge", "-u", "-bk", "--binpkg-respect-use=y", "genkernel", "eclean-kernel", "linux-sources", kernelpkg], 
        env={"PATH":os.environ["PATH"],"USE":"symlink","ACCEPT_LICENSE":"linux-fw-redistributable no-source-code"})

    if not menuconfig and is_kernel_built():
        print("Kernel already built. if you want to rebuild with different config, use --menuconfig")
        return
    #else

    kernel_id = get_kernel_id()
    if os.path.isfile(cache_file_name) and kernel_id == get_kernel_id_from_kernel_cache(cache_file_name):
        print("Kernel cache for %s found. Using it." % kernel_id)
        subprocess.check_call(["tar", "-C", "/", "-xf", cache_file_name])
        subprocess.check_call(["make", "prepare"], cwd="/usr/src/linux")
        return
    #else
    build_kernel(config, menuconfig)
    generate_kernel_cache(cache_file_name)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--config", default="/kernel-config", help="Specify kernel config file")
    parser.add_argument("--menuconfig", action="store_true", default=False, help="Run menuconfig(implies --nocache)")
    parser.add_argument("kernelpkg", default="gentoo-sources", nargs='?', help="Kernel package ebuild name")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.debug("Debug mode enabled")
    else:
        logging.basicConfig(level=logging.INFO)

    main(args.kernelpkg, args.config, args.menuconfig)
    print("Done.")
