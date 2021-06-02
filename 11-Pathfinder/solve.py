hardcoded = b'CYHSZZBU'

for i in range(len(hardcoded)):
    for j in range(0x41, 0x5b):
        if ((j - 0x41 + ((i + 8) * 0x1f)) % 0x1a) + 0x41 == hardcoded[i]:
            print(chr(j), end='')

print()
