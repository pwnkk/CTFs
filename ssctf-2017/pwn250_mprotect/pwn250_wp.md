pwn250 
静态编译
ret2syscall 直接可以做 ROPgadget 自动生成即可
如果禁用了execve 那么也会shellcode也无效, 单独禁用system函数才行


函数介绍
<1>. mprotect

int mprotect(const void *start, size_t len, int prot);
mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。

<2>. mmap

void mmap(void start,size_t length,int prot,int flags,int fd,off_t offset);
mmap()函数把指定或随机分配的地址内存，以prot权限映射到自start开始的，长度为length，而且为PAGE_SIZE单位的地址。
利用思路

<1>. 将shellcode写进一段具有可写权限的段里，然后用mprotect将对应的段修改为可执行，再跳到布置好的shellcode里。

<2>. 用mmap获取一段rwx权限的内存，映射到指定地址处，然后将shellcode写入映射好的内容存里，接着跳入布置好的shellcode中。


为什么使用mprotect 
