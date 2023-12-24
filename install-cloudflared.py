#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: shimarin
# Created: 2023-12-24

import os,json, urllib.request, argparse

MACHINE=os.uname()[4]

def get_tag_name(user,repo):
    url = "https://api.github.com/repos/%s/%s/releases/latest" % (user,repo)

    request = urllib.request.Request(url)
    with urllib.request.urlopen(request) as response:
        data = json.loads(response.read().decode())
        return data.get("tag_name")

def determine_download_url():
    tag_name = get_tag_name("cloudflare", "cloudflared")
    arch = "amd64" if MACHINE == "x86_64" else "arm64" if MACHINE == "aarch64" else MACHINE
    return "https://github.com/cloudflare/cloudflared/releases/download/%s/cloudflared-linux-%s" % (tag_name, arch)

def complete_installation(cloudflared_path, config_dir, config_yml):
    os.chmod(cloudflared_path, 0o755)
    os.makedirs(config_dir, exist_ok=True)
    if not os.path.exists(config_yml):
        with open(config_yml, "w") as f:
            f.write("url: http://localhost:80\n")
            f.write("tunnel: YOUR_TUNNEL_ID_HERE\n")
            f.write("credentials-file: %s/YOUR_TUNNEL_ID_HERE.json\n" % config_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Download cloudflared binary')
    parser.add_argument('--save-to', default="/usr/local/bin/cloudflared")
    args = parser.parse_args()

    config_dir = "/usr/local/etc/cloudflared"
    config_yml = os.path.join(config_dir, "config.yml")

    if os.path.isfile(args.save_to):
        print("Already installed.")
    else:
        url = determine_download_url()
        install_dir = os.path.dirname(args.save_to)
        if not os.path.isdir(install_dir): os.makedirs(install_dir)
        print("Downloading %s to %s" % (url, args.save_to))
        urllib.request.urlretrieve(url, args.save_to)
        complete_installation(args.save_to, config_dir, config_yml)
        print("Installation complete.")
    print("---")
    print("1. `cloudflared tunnel login` to login.")
    print("2. `cloudflared tunnel create <tunnel name>` to create a tunnel.  json file will be created in ~/.cloudflared/")
    print("3. Move tunnel json file under ~/.cloudflared/ to %s and edit %s" % (config_dir, config_yml))
    print("4. `cloudflared service install` to install service.  Service will automaticall be started.")
