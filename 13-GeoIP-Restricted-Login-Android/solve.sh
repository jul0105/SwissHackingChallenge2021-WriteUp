#!/bin/bash

# Setup reference output
curl "https://ja3er.com/img/$(printf "CH.Zermatt.%04d" 0000 | md5sum | cut --bytes=-32)" > output 2> /dev/null

# Loop over 4 digit PIN
for i in {0..9999}
do
    printf "CH.Zermatt.%04d\n" $i
    
    # Get response from external service
    curl "https://ja3er.com/img/$(printf "CH.Zermatt.%04d" $i | md5sum | cut --bytes=-32)" > output2 2> /dev/null
    
    # Compare response with reference. If different, it might be the valid PIN
    diff output output2
done

