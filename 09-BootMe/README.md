# BootMe

> Author : jul0105
> Date : 27.03.2021



## Challenge info

**Release** : Bundle 3 (27.03)

**Difficulty** : Easy

**Goal** : You'll find the flag on the luci login page (http, port 80) of the router.



## Solve

1. With `file` we identify the `.elf` file as an ELF 32-bits executable on MIPS architecture

```
BootMe_openwrt-malta-le-vmlinux-initramfs.elf: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, stripped
```

2. Here is how to run it :

```bash
qemu-system-mipsel -nic user,hostfwd=tcp::8080-:80 -nographic -m 256 -kernel BootMe_openwrt-malta-le-vmlinux-initramfs.elf
```

3. In the BusyBox shell, execute these commands to allow access on port 80 from the host :

```bash
uci add firewall rule &&
uci set firewall.@rule[-1].src='wan' &&
uci set firewall.@rule[-1].target='ACCEPT' &&
uci set firewall.@rule[-1].proto='tcp' &&
uci set firewall.@rule[-1].dest_port='80' &&
uci commit firewall && 
/etc/init.d/firewall restart
```

4. Now we can access LuCI web interface with http://localhost:8080/cgi-bin/luci/
5. The flag is at the bottom of the page :

```
hl{YAY_I_WAS_BOOTED}
```



Resource : https://openwrt.org/docs/guide-user/virtualization/qemu