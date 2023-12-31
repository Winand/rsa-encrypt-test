SRC_FILE="image.png"
DST_FILE="image-dec.png"

OUTPUT_DIR="./rsa-output"
PASSWORD="$OUTPUT_DIR/password"
PUB_KEY="./keys/client/ssh_key.pub"
PRIV_KEY="./keys/client/ssh_key"

mkdir $OUTPUT_DIR

# Encryption
openssl rand -hex -out $PASSWORD 32
openssl enc -p -aes-256-cbc -pbkdf2 -in $SRC_FILE -out $OUTPUT_DIR/$SRC_FILE.enc -pass file:$PASSWORD
ssh-keygen -f $PUB_KEY -e -m PKCS8 > $OUTPUT_DIR/pem.pub  # note: same result for $PRIV_KEY input
openssl rsautl -encrypt -inkey $OUTPUT_DIR/pem.pub -pubin -in $PASSWORD -out $PASSWORD.enc

# Decryption
# https://serverfault.com/a/1030084
cp $PRIV_KEY $OUTPUT_DIR/pem
ssh-keygen -p -N "" -m pem -f $OUTPUT_DIR/pem
openssl rsautl -decrypt -inkey $OUTPUT_DIR/pem -in $PASSWORD.enc -out $PASSWORD.dec
openssl enc -d -p -aes-256-cbc -pbkdf2 -salt -in $OUTPUT_DIR/$SRC_FILE.enc -out $DST_FILE -pass file:$PASSWORD.dec
