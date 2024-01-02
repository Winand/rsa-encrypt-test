SRC_FILE="image.png"
DST_FILE="image-dec.png"

OUT_DIR="./rsa-output"
PASSWORD_FILE="$OUT_DIR/password"
CLIENT_PUB_KEY="./keys/client/ssh_key.pub"
CLIENT_PRIV_KEY="./keys/client/ssh_key"
SERVER_PUB_KEY="./keys/server/ssh_key.pub"
SERVER_PRIV_KEY="./keys/server/ssh_key"

mkdir -p $OUT_DIR

echo "---Encryption---"
openssl rand -hex -out $PASSWORD_FILE 32
openssl enc -p -aes-256-cbc -pbkdf2 -pass file:$PASSWORD_FILE -in $SRC_FILE -out $OUT_DIR/$SRC_FILE.enc  # -nosalt
ssh-keygen -f $CLIENT_PUB_KEY -e -m PKCS8 > $OUT_DIR/client_pem.pub  # note: same result for $CLIENT_PRIV_KEY input
openssl rsautl -encrypt -inkey $OUT_DIR/client_pem.pub -pubin -in $PASSWORD_FILE -out $PASSWORD_FILE.enc

echo "---Signing---"
# https://serverfault.com/a/1030084
cp $SERVER_PRIV_KEY $OUT_DIR/server_pem
ssh-keygen -p -N "" -m pem -f $OUT_DIR/server_pem
openssl dgst -sign $OUT_DIR/server_pem -keyform PEM -sha256 -out $OUT_DIR/$SRC_FILE.sign -binary $OUT_DIR/$SRC_FILE.enc

echo "---Verification---"
ssh-keygen -f $SERVER_PUB_KEY -e -m PKCS8 > $OUT_DIR/server_pem.pub
openssl dgst -verify $OUT_DIR/server_pem.pub -keyform PEM -sha256 -signature $OUT_DIR/$SRC_FILE.sign -binary $OUT_DIR/$SRC_FILE.enc
if [ $? -ne 0 ]; then exit 1; fi

echo "---Decryption---"
cp $CLIENT_PRIV_KEY $OUT_DIR/client_pem
ssh-keygen -p -N "" -m pem -f $OUT_DIR/client_pem
openssl rsautl -decrypt -inkey $OUT_DIR/client_pem -in $PASSWORD_FILE.enc -out $PASSWORD_FILE.dec
openssl enc -d -p -aes-256-cbc -pbkdf2 -pass file:$PASSWORD_FILE.dec -in $OUT_DIR/$SRC_FILE.enc -out $DST_FILE  # -nosalt
