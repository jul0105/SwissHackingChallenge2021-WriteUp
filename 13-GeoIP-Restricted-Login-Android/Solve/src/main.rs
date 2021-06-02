use md5;
use rayon::prelude::*;

// FLAG : SCS21{R3wire-Your-Br@in-Cr@ck-The-Ch@lleng3s}

lazy_static::lazy_static! {
    static ref CHARSET: [char; 10] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
}

fn main() {
    println!("Starting...");
    let a: Vec<i32> = (0..(CHARSET.len() as i32).pow(4)).into_par_iter() // TODO into_par_iter
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
