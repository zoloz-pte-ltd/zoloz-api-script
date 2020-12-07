#!/bin/sh

urlsafe_encode() {
  local length="${#1}"
  for (( i = 0; i < length; i++ )); do
    local c="${1:i:1}"
    case $c in
      [a-zA-Z0-9.~_-]) printf "$c" ;;
    *) printf "$c" | xxd -p -c1 | while read x;do printf "%%%s" "$x";done
  esac
done
}

# set -x

# Initialize variables default:
clientid='2089012345678900'
privkey='merchant-priv-key.pem'
pubkey='zoloz-pub-key.pem'
payload='{\n  "title": "hello",\n  "description": "just for demonstration."\n}'
api='/api/v1/zoloz/authentication/test'
reqtime=$(date +%F'T'%T%z)
host='https://sg-production-api.zoloz.com'
encryption=0

OPTIND=1
while getopts ":?hvc:p:P:c:a:d:f:H:ek:t:" opt; do
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
    H)  host=$OPTARG
        ;;
    e)  encryption=1
        ;;
    k)  aeskey=$OPTARG
        ;;
    d)  payload=$OPTARG
        ;;
    f)  infile=$OPTARG
        ;;
    :)
      echo "$0: Must supply an argument to -$OPTARG." >&2
      exit 1
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 2
      ;;
    esac
done
shift $((OPTIND-1))
[ "${1:-}" = "--" ] && shift

if [ "$clientid" == "" ] ; then
    echo "client id is not specified." >&2
    exit -1
fi

if [ "$privkey" == "" ] ; then
    echo "merchant private key is not specified." >&2
    exit -1
fi

if [ "$pubkey" == "" ] ; then
    echo "zoloz private key is not specified." >&2
    exit -1
fi

echo "client id: $clientid"
echo "merchant private key file: $privkey"
echo "zoloz public key file: $pubkey"
echo "request time: $reqtime"
echo "host: $host"
echo "api: $api"

echo "encryption: $encryption"
if [ "$encryption" == "1" ] ; then
    if [ "$aeskey" == "" ] ; then
        export LC_CTYPE=C; aeskey=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 32 | head -n 1)
    fi
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
echo "signature: $signature"

url="$host$api"
echo "url: $url"

if [ "$encryption" == "1" ] 
then
  curl \
    -H "Content-Type: text/plain" \
    -H "Client-Id: $clientid" \
    -H "Request-Time: $reqtime" \
    -H "Signature: algorithm=RSA256, signature=$(urlsafe_encode $signature)" \
    -H "Encryption: algorithm=RSA_AES, symmetricKey=$enckey" \
    -d "$body" \
    "$url"
else
  curl \
    -H "Content-Type: application/json; charset=UTF-8" \
    -H "Client-Id: $clientid" \
    -H "Request-Time: $reqtime" \
    -H "Signature: algorithm=RSA256, signature=$(urlsafe_encode $signature)" \
    -d "$body" \
    "$url"
fi
