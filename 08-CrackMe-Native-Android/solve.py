x0 = [121, 134, 239, 213, 16, 28, 184, 101, 150, 60, 170, 49, 159, 189, 241, 146, 141, 22, 205, 223, 218, 210, 99, 219, 34, 84, 156, 237, 26, 94, 178, 230, 27, 180, 72, 32, 102, 192, 178, 234, 228, 38, 37, 142, 242, 142, 133, 159, 142, 33]

x5 = b'\x80\xe3\xda\xc7\x2e\xf1\xa2\x91\x6b\xdc\x6b\xb5\xe5\xaf\x3f\xb9\xee\x5b\x26\x92\x66\xc5\xcb\xde\x81\x79\xda'

x7 = b'\x4c\x7b\x73\x6f\x72\x72\x79\x2e\x74\x68\x69\x73\x2e\x69\x73\x2e\x4e\x4f\x54\x2e\x74\x68\x65\x2e\x66\x6c\x61'

x9 = b'\xd0\x45\x28\x76\x6f\xf3\x5a\xf4\xc7\xce\xfb\xc3\x7f\x48\xce\x3c\x3a\x0b\xf1\x53\xb1\x4b\xb9\x5e\xa2\x65\x77'


for i in range(27):
    result = int(x0[i]) ^ x5[i] ^ x9[i] ^ x7[len(x7) - 1 - i]
    print(chr(result), end='')

print()
