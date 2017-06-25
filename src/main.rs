extern crate sodiumoxide;
extern crate rustc_serialize as serialize;
extern crate rustc_serialize;

extern crate argparse;
use argparse::{ArgumentParser, StoreTrue, Store};

use std::str;
use std::io;
use sodiumoxide::crypto::stream::xsalsa20;


// found here: https://github.com/ustulation/rust_pocs
fn get_base64_config() -> serialize::base64::Config {
    rustc_serialize::base64::Config {
        char_set   : serialize::base64::CharacterSet::Standard,
        newline    : serialize::base64::Newline::LF,
        pad        : true,
        line_length: None,
    }
}

fn sodium_secretbox_test() {
    use sodiumoxide::crypto::secretbox;

    let key = secretbox::gen_key();
    let nonce = secretbox::gen_nonce();
    let plaintext = b"some data";
    let ciphertext = secretbox::seal(plaintext, &nonce, &key);
    let their_plaintext = secretbox::open(&ciphertext, &nonce, &key).unwrap();
    assert!(plaintext == &their_plaintext[..]);
}

fn sodium_stream_test() {
    use sodiumoxide::crypto::stream;

    let key = stream::gen_key();
    let nonce = stream::gen_nonce();
    let plaintext = &mut [0, 1, 2, 3];
    // encrypt the plaintext
    stream::stream_xor_inplace(plaintext, &nonce, &key);
    // decrypt the plaintext
    stream::stream_xor_inplace(plaintext, &nonce, &key);
    assert_eq!(plaintext, &mut [0, 1, 2, 3]);
}

// Does Rust support default function arguments? Default num_of_lines could be 1
fn print_lines_of_clouds(num_of_lines: u16) {
    let sun_behind_cloud = '⛅';

    // line_length should be greater than 0, could not find static_assert
    // better solution would be getting line weight from cmd
    let line_length = 50;

    let mut i = 0;
    loop {
        if i != 0 && ( i % line_length == 0 ) {
            print!("\n");
        }
        if i >= ( num_of_lines * line_length )  {
            break;
        }
        print!("{} ", sun_behind_cloud);
        i += 1;
    }
}

fn read_cmd_message() -> Vec<u8> {
    use std::io::Write;

    print!("Please write your message (end with <Enter>) : ");

    io::stdout().flush()
        .expect("Failed to flush stdout");
    let mut msg = String::new();
    io::stdin().read_line(&mut msg)
        .expect("Failed to read line");

    let mut msg_vec = msg.into_bytes();

    // get rid of new_line symbol at the end
    msg_vec.pop();
    msg_vec
}

fn print_vec_hexbytes(vector: &Vec<u8>) {
    for x in vector {
        print!("{:x}",x);
    }
    print!("\n");
}

fn from_vec_hexbytes(vector: &Vec<u8>) -> Vec<u8> {
    let mut hex_str = String::new();
    for x in vector {
        let ch = x.clone() as char;
        hex_str.push(ch);
        //print!("{:?}, ",charchar);
    }

    let input_chars: Vec<_> = hex_str.chars().collect();

    input_chars.chunks(2).map(|chunk| {
        let first_byte = chunk[0].to_digit(16).unwrap();
        let second_byte = chunk[1].to_digit(16).unwrap();
        ((first_byte << 4) | second_byte) as u8
    }).collect()
}

fn print_vec_bytes_as_string(vector: &Vec<u8>) {
    for x in vector {
        let ch : char = x.clone() as char;
        print!("{}",ch);
    }
    print!("\n");
}

fn xsalasa20_get_zero_nonce() -> xsalsa20::Nonce {
    let arr : [u8;24] = [0;24];
    let nonce = xsalsa20::Nonce::from_slice(&arr).unwrap();
    nonce
}

fn xsalasa20_key_compress(key: &xsalsa20::Key) -> String {
    use serialize::base64::{ToBase64};

    let key_b64 = key.0.to_base64(get_base64_config());
    key_b64
}

fn xsalasa20_key_decompress(key_b64: &String) -> xsalsa20::Key {
    use serialize::base64::{FromBase64};

    let mut key_from_b64 = key_b64.from_base64().ok().unwrap();

    let xsalsa20_key = xsalsa20::Key::from_slice(key_from_b64.as_mut_slice())
        .unwrap();
    xsalsa20_key
}

fn crypto_stream_encrypt_inter() {
    use sodiumoxide::crypto::stream::xsalsa20;

    let zero_nonce = xsalasa20_get_zero_nonce();

    let mut message = read_cmd_message();
    while message.len() == 0 {
        println!("Empty message, try again: ");
        message = read_cmd_message();
    }

    let key = xsalsa20::gen_key();
    let key_compressed = xsalasa20_key_compress(&key);

    print!("Key generated for this message ");
    println!("(keep secure, it is needed to decrypt your message):\n{}", key_compressed);

    // encrypt
    xsalsa20::stream_xor_inplace(message.as_mut_slice(), &zero_nonce, &key);
    println!("Ciphertext:");
    print_vec_hexbytes(&message);
}

fn crypto_stream_encrypt(mut message: Vec<u8>) {
    use sodiumoxide::crypto::stream::xsalsa20;

    let zero_nonce = xsalasa20_get_zero_nonce();

    while message.len() == 0 {
        println!("Empty message, try again: ");
        message = read_cmd_message();
    }

    let key = xsalsa20::gen_key();
    let key_compressed = xsalasa20_key_compress(&key);

    print!("Key generated for this message ");
    println!("(keep secure, it is needed to decrypt your message):\n{}", key_compressed);

    // encrypt
    xsalsa20::stream_xor_inplace(message.as_mut_slice(), &zero_nonce, &key);
    println!("Ciphertext");
    print_vec_hexbytes(&message);
}

fn crypto_stream_decrypt(key: String, cipher: Vec<u8>) {
    let zero_nonce = xsalasa20_get_zero_nonce();
    let k_decompressed = xsalasa20_key_decompress(&key);
    let mut hmm = from_vec_hexbytes(&cipher);

    // decrypt
    xsalsa20::stream_xor_inplace(hmm.as_mut_slice(), &zero_nonce, &k_decompressed);
    print!("Decrypted message:\n");
    print_vec_bytes_as_string(&hmm);
}

fn main() {
    sodiumoxide::init();
    sodium_secretbox_test();
    sodium_stream_test();

    print_lines_of_clouds(1);

    let mut interactive = false;
    let mut symmetric_msg : String = String::from("");
    let mut symmetric_cip : String = String::from("");
    let mut key : String = String::from("");
    {  // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("Simple message symmetric encryption, with random key using xsalsa20");
        ap.refer(&mut interactive)
            .add_option(&["-i", "--interactive"], StoreTrue,
            "interactive mode (step by step) for message encryption");
        ap.refer(&mut symmetric_msg)
            .add_option(&["-c", "--symmetric"], Store,
            "encrypt message with random key. Gives key and cipher text as output");
        ap.refer(&mut key)
            .add_option(&["-k", "--key"], Store,
            "key is needed to decrypt message, you have to provide it if you using (-d, --decrypt) options");
        ap.refer(&mut symmetric_cip)
            .add_option(&["-d", "--decrypt"], Store,
            "decrypt ciphertext with provided key");
        ap.parse_args_or_exit();
    }

    if interactive {
        crypto_stream_encrypt_inter();
        print_lines_of_clouds(1);
        return ();
    }

    if symmetric_msg.len() != 0 && symmetric_cip.len() != 0 {
        println!("You should decide whether you want to encrypt or decrypt the message (see help)");
        return ();
    }
    if symmetric_msg.len() != 0 {
        println!("Msg to encrypt: {}", symmetric_msg);

        crypto_stream_encrypt(symmetric_msg.into_bytes());
        print_lines_of_clouds(1);
    } else if symmetric_cip.len() != 0 {
        assert!(key.len() != 0, "If you want to decrypt message, you should provide the key (-k option, see help)");
        crypto_stream_decrypt(key, symmetric_cip.into_bytes());
        print_lines_of_clouds(1);
    } else {
        println!("Nothing to do. Goodbye");
        print_lines_of_clouds(1);
    }
}
