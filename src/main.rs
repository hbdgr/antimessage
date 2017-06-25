extern crate sodiumoxide;
extern crate rustc_serialize as serialize;

extern crate argparse;
use argparse::{ArgumentParser, StoreTrue, Store};

use std::str;
use std::vec;
use std::io;
use sodiumoxide::crypto::stream::xsalsa20;


struct UserNode {
    prv_key: u32,
    pub_key: u32,
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

fn xsalasa20_key_compress(key: &xsalsa20::Key ) {
    println!("{:?}", key);
}

fn crypto_stream_encrypt() {
    use sodiumoxide::crypto::stream::xsalsa20;

    let key = xsalsa20::gen_key();

    let zero_nonce = xsalasa20_get_zero_nonce();

    let mut message = read_cmd_message();
    println!("Key generated for this message (save if, if you want to decrypt your message)");
    xsalasa20_key_compress(&key);

    print!("Befor encryption: ");
    print_vec_bytes_as_string(&message);
    // encrypt
    xsalsa20::stream_xor_inplace(message.as_mut_slice(), &zero_nonce, &key);
    println!("Ciphertext");
    print_vec_hexbytes(&message);

    // decrypt
    xsalsa20::stream_xor_inplace(message.as_mut_slice(), &zero_nonce, &key);
    //assert_eq!(plaintext, &mut [0, 1, 2, 3]);
    print!("After decryption: ");
    print_vec_bytes_as_string(&message);
}

fn main() {
    sodiumoxide::init();
    sodium_secretbox_test();
    sodium_stream_test();

    print_lines_of_clouds(3);

    let mut interactive = false;
    let mut symmetric : String = String::from("");
    {  // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("Simple message symmetric encryption, with random key using xsalsa20");
        ap.refer(&mut interactive)
            .add_option(&["-i", "--interactive"], StoreTrue,
            "interactive mode (step by step) for message encryption");
        ap.refer(&mut symmetric)
            .add_option(&["-c", "--symmetric"], Store,
            "encrypt message with random key. Gives key and cipher text as output");
        ap.parse_args_or_exit();
    }

    if interactive {
        crypto_stream_encrypt();
        return ();
    }

    if symmetric.len() != 0 {
        println!("Msg to encrypt: {}", symmetric);
    } else {
        println!("Goodbye");
        print_lines_of_clouds(3);
    }
}
