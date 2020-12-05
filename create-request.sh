#!/bin/sh

set -x

# Initialize variables default:
clientid='2089012345678900'
privkey='merchant-priv-key.pem'
pubkey='zoloz-pub-key.pem'
payload='{\n  "title": "hello",\n  "description": "just for demonstration."\n}'
api='/api/v1/zoloz/authentication/test'
reqtime=$(date +%F'T'%T%z)

OPTIND=1
#while getopts "h?vcPpatedf:" opt; do
while getopts "h?vet:" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    v)  verbose=1
        ;;
    t)  reqtime=$OPTARG
        ;;
    c)  clientid=$OPTARG
        ;;
    P)  privkey=$OPTARG
        ;;
    p)  pubkey=$OPTARG
        ;;
    a)  api=$OPTARG
        ;;
    e)  aeskey=$OPTARG
        if [ "$aeskey" == "" ]
        then
            export LC_CTYPE=C; aeskey=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 32 | head -n 1)
        fi
        ;;
    d)  payload=$OPTARG
        ;;
    f)  infile=$OPTARG
        ;;
    esac
done
shift $((OPTIND-1))
[ "${1:-}" = "--" ] && shift

if [ "$clientid" == "" ] 
then
    echo "client id is specified." >&2
fi

if [ "$privkey" == "" ] 
then
    echo "merchant private key is specified." >&2
fi

if [ "$pubkey" == "" ] 
then
    echo "zoloz private key is specified." >&2
fi

echo "client id: $clientid"
echo "merchant private key file: $privkey"
echo "zoloz public key file: $pubkey"
echo "api: $api"
echo "request time: $reqtime"

if [ "$aeskey" != "" ] 
then
  echo "aes128 key: 0x$aeskey"
  enckey=$(printf $aeskey | xxd -r -p | openssl rsautl -encrypt -pkcs -pubin -inkey zoloz-pub-key.pem | base64)
  echo "encrypted aes128 key: $enckey"
  body=$(printf "$payload" | openssl enc -e -aes-128-ecb -K $aeskey | base64)
else
  body="$payload"
fi

content="POST $api\n$clientid.$reqtime.$body"
echo "content: '$content'"

signature=$(printf "$content" | openssl dgst -sign $privkey -keyform PEM -sha256 | base64)
echo "signature: '$signature'"

if [ "$aeskey" != "" ] 
then
  echo "curl \\
    -H 'Content-Type: text/plain' \\
    -H 'Client-Id: $clientid' \\
    -H 'Request-Time: $reqtime' \\
    -H 'Signature: algorithm=RSA256, signature=$signature' \\
    -H 'Encryption: algorithm=RSA_AES, symmetricKey=$enckey' \\
    -d '$body' \\
    https://sg-production-api.zoloz.com/api/v1/zoloz/authentication/test"
else
  echo "curl \\
    -H 'Content-Type: application/json; charset=UTF-8' \\
    -H 'Client-Id: $clientid' \\
    -H 'Request-Time: $reqtime' \\
    -H 'Signature: algorithm=RSA256, signature=$signature' \\
    -d '$body' \\
    https://sg-production-api.zoloz.com/api/v1/zoloz/authentication/test"
fi
