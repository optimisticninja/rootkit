# rootkit

A rootkit that supports kernel 4.17.0 onward (up to 6.0.7 as of writing this) for security research purposes.

## Requirements

* A Linux host (Assumes Arch Linux [btw] running on hardened kernel)
    - If running a different host, adjust `scripts/setup-vagrant.sh` accordingly to relevant package manager
* Kernel headers installed
* Working libvirt installation
    - Not necessary but you will need to adjust the `Vagrantfile` for a different provider
* Firewall rules that will allow DHCP/DNS to rootkit node
    - Allow `virbr<num>` to forward traffic to itself
    - Allow UDP 53,67 on that same interface for DHCP/DNS
* [bear](https://github.com/rizsotto/Bear) to generate `compile_commands.json`
    - May be optional, I develop in Vim with Syntastic and it was necessary
    - TODO: Errant header files after bear generation
    - TODO: Investigate script dropped into kernel source by Google dev

## Running

You can either test on your own host or within Vagrant (HIGHLY RECOMMENDED, don't kernel panic your host during development)

### Vagrant

```bash
$ ./scripts/setup-vagrant.sh # Assumes Arch Linux host
$ make
$ vagrant up --provision # This should rsync repo directory to `/vagrant`
$ vagrant ssh rootkit1
$ export PS1="(vagrant) $PS1"
(vagrant) $ cd /vagrant
(vagrant) $ sudo insmod rootkit.ko
```

### Host (Ill-advised if developing/adding features)

```bash
$ make
$ sudo insmod rootkit.ko
```

## Features

* syscall hooks
    - `sys_kill` - Our "signal API"
        - signal 62 hides supplied pid
            - ex: `kill -62 $$      # hide the shell this command is run from`
            - ex: `kill -62 31337   # hide the PID (31337)
        - signal 63 hides linux kernel module from `lsmod`
            - ex: `lsmod | grep rootkit; kill -63 $$; lsmod | grep rootkit # show it exists, hide it, see it missing`
        - signal 64 escalates process executing from to root privileges
            - ex: `kill -64 $$ # escalate current shell`
    - `sys_getdents(64)` - Hook to filter files/folders/PIDs
        - Hides dirents prefixed with `...`
            - ex: `mkdir ...test; touch ...test2; ls # find them missing from output`
        - Hides/unhides process(es) specified in kill signal 62
            - ex: `myproc=$$; kill -62 $$; ps aux | grep $myproc # hide current shell from ps`
    - `tcp4_seq_show` - Hook to filter TCP ports
        - TODO: Currently hardcoded 8080, make kill signal for addition/removal and multiple ports
        - TODO: Example

## TODO

**Docs/setup**
* Add net-tools, gnu-netcat to setup

**Bugfix**
* Fix crash on rmmod

**Research**
* dirty cred assignment so root privs via escalation can be hidden from `ps`

**Features**
* Hide ports
* Hiding logged in users
* Hijack character devices for breaking random/urandom
* Memory loader/kpatch for avoiding insmod

**Enhancements**
* utilize `pid` from kill signal to escalate other processes than $$
    - This may be protected for outside processes
* remove logging in release builds
* hide multiple default ports/add ports

