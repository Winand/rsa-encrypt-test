# Key generation
```bash
rm -rf ./keys && mkdir -p ./keys/client ./keys/server
ssh-keygen -t rsa -q -N "" -f ./keys/client/ssh_key
ssh-keygen -t rsa -q -N "" -f ./keys/server/ssh_key
```

# Links
- [Use Go to encrypt message with ssh-rsa public key <...>](https://stackoverflow.com/questions/71960918/use-go-to-encrypt-message-with-ssh-rsa-public-key-which-then-can-be-decrypted-us)
- [Encrypting Data With SSH Keys and Golang](https://earthly.dev/blog/encrypting-data-with-ssh-keys-and-golang/)
- [Encrypt/Decrypt a file using RSA public-private key pair](https://kulkarniamit.github.io/whatwhyhow/howto/encrypt-decrypt-file-using-rsa-public-private-keys.html)
    - [Using -iter or -pbkdf2 would be better](https://unix.stackexchange.com/q/507131)
    - [How to use ssh-rsa public key to encrypt a text?](https://superuser.com/a/576558)
- [Create an OpenSSL signature](https://xn--verschlsselt-jlb.it/openssl-first-steps/#:~:text=Create%20an%20OpenSSL%20signature)

# Notes
- EdDSA [Ed25519](https://ru.wikipedia.org/wiki/EdDSA#Ed25519) is used for signing, not encrypting
