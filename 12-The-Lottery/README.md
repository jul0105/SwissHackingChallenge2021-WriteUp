# The Lottery

> Author : jul0105
> Date : 13.04.2021



## Challenge info

**Release** : Bundle 4 (10.04)

**Difficulty** : Medium

**Goal** : Can you win the lottery?



## Analysis

1. The server draw 6 random number with js function `Math.random()`. If the user choose the right numbers, he win.
2. `Math.random()` use XorShift128+ internally. It is not a cryptographicaly secure PRNG.
3. This POC (https://github.com/TACIXAT/XorShift128Plus) provide a way to get the next values that will be picked by `Math.random()`. But it require to input the 5 previous random values.
4. The problem is that our lottery doesn't print the full random values because it is floored. It only print a part of it :

```javascript
const number = Math.floo(Math.random() * 10000);
```

So we end up with truncated random values.

5. **d0nutptr** made a great talk on this particular subject with a working POC : https://github.com/d0nutptr/v8_rand_buster.
6. His python script allow to get the next *floored* random value when inputed at least 14 *floored* random values.



## Solving

Using d0nutptr's script, I was able to get the flag with my bash script :

```bash
base_url="https://acc0c878-4a66-4ebd-b6f1-43251e27701f.idocker.vuln.land"

printf "" > codes.txt

echo "[+] Getting 18 random numbers from the lottery"
for i in 1 2 3
do
    curl --data '{"guess":[0,0,0,0,0,0]}' -H 'content-type: application/json' ${base_url}/make_guess | cut --delimiter='[' --fields=2 | cut --delimiter=']' --fields=1 | grep ',' | sed "s/,/\n/g" >> codes.txt
done

echo "[+] Calculate seed (take some time)"
seeds=$(cat codes.txt | tac | python v8_rand_buster/xs128p.py --multiple 10000 --lead 6)
echo $seeds

echo "[+] Next numbers"
python v8_rand_buster/xs128p.py --multiple 10000 --gen ${seeds},24 > numbers.txt
next_numbers=$(cat numbers.txt | head --lines=6 | tac | tr '\n' ' ')
echo $next_numbers

echo "[+] Getting the Flag"
curl --data $(printf '{"guess":[%s,%s,%s,%s,%s,%s]}' $next_numbers) -H 'content-type: application/json' ${base_url}/make_guess 


rm codes.txt
rm numbers.txt
```



Flag:

```
60cb3912-2d81-4844-ae90-e84c92413d5c%
```

