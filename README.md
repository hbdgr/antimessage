# AntiMessage

Simple command line tool, written in Rust, that encrypts/decrypts messages with random generated keys.

## Build:
```
$ git clone https://github.com/hbdgr/antimessage.git
$ cd antimessage
$ cargo build
```

## Usage:
```
$./target/debug/antimessage --help
Usage:
    ./target/debug/antimessage [OPTIONS]

Simple message symmetric encryption, with random key using xsalsa20

optional arguments:
  -h,--help             show this help message and exit
  -i,--interactive      interactive mode (step by step) for message encryption
  -c,--symmetric SYMMETRIC
                        encrypt message with random key. Gives key and cipher
                        text as output
  -k,--key KEY          key is needed to decrypt message, you have to provide
                        it if you using (-d, --decrypt) options
  -d,--decrypt DECRYPT  decrypt ciphertext with provided key
```

## Example of use:

Encryption:
```
./target/debug/antimessage -c "Encrypt Me"
⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅
Msg to encrypt: Encrypt Me
Key generated for this message (keep secure, it is needed to decrypt your message):
TSWwuVP/V/YaWInsJj6tqMgqRbMBa4n4AdBc0kc/6D8=
Ciphertext:
fa406e4cea3042cefe21
⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅
```

Decryption:
```
./target/debug/antimessage -k TSWwuVP/V/YaWInsJj6tqMgqRbMBa4n4AdBc0kc/6D8= -d fa406e4cea3042cefe21
⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅
Decrypted message:
Encrypt Me
⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅ ⛅
```
