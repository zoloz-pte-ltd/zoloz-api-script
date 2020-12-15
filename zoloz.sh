#!/bin/bash 
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

urlsafe_decode() {
    local data=${1//+/ }
    printf '%b' "${data//%/\x}"
}

parse_header() {
  local header_file=${1//+/ }
  local header_key=${2//+/ }
  local subkey=${3//+/ }
  local header_line=$(grep "$header_key: " "$header_file" | head -1 | tr -d '\r\n')
  local header_val=${header_line##*": "}
  if [ "$subkey" == "" ] ; then
    echo "$header_val"
  else
    remain=$header_val", "
    while [[ $remain ]]; do
      subitem=${remain%%", "*};
      if [ "${subitem%%"="*}" == "$subkey" ] ; then
        subval=${subitem#*"="}
        break;
      fi
      remain=${remain#*", "};
    done;
    echo "$subval"
  fi
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
while getopts ":?hvc:p:P:c:a:d:f:H:ek:t:l" opt; do
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
    l)  skip_response_validation=1
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

    enckey=$(printf $aeskey | xxd -r -p | openssl rsautl -encrypt -pkcs -pubin -inkey "$pubkey" | base64)
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

resp_header_file=$(mktemp)
echo "temporary response header file: $resp_header_file"

if [ "$encryption" == "1" ] 
then
  respbody=$(curl \
    -H "Content-Type: text/plain" \
    -H "Client-Id: $clientid" \
    -H "Request-Time: $reqtime" \
    -H "Signature: algorithm=RSA256, signature=$(urlsafe_encode $signature)" \
    -H "Encrypt: algorithm=RSA_AES, symmetricKey=$(urlsafe_encode $enckey)" \
    -d "$body" \
    -s -D "$resp_header_file" \
    "$url")
else
  respbody=$(curl \
    -H "Content-Type: application/json; charset=UTF-8" \
    -H "Client-Id: $clientid" \
    -H "Request-Time: $reqtime" \
    -H "Signature: algorithm=RSA256, signature=$(urlsafe_encode $signature)" \
    --data-binary @<(printf "$body") \
    -s -D "$resp_header_file" \
    "$url")
fi

echo "response body: '$respbody'"
resp_header=$(cat "$resp_header_file")
echo $"response header: \n$resp_header"
resp_signature=$(urlsafe_decode $(parse_header "$resp_header_file" "signature" "signature"))
echo "response signature: $resp_signature"
resptime=$(parse_header "$resp_header_file" "response-time")
echo "response time: $resptime"

content="POST "$api"\n"$clientid"."$resptime".""$respbody"
echo "content to be verified: '$content'"

if [ "$skip_response_validation" == "1" ] ; then
  echo "skip response validation" >&2
else
  # verify the signature using zoloz public key
  verify_resp=$(printf "$content" | openssl dgst -verify "$pubkey" -keyform PEM -sha256 -signature <(printf $resp_signature | base64 -d))
  echo $verify_resp
  if [ "$verify_resp" != "Verified OK" ] ; then
    exit -1
  fi
fi

resp_content_type=$(parse_header "$resp_header_file" "content-type")
echo "response content type: $resp_content_type"
if [[ "$resp_content_type" == *"text/plain"* ]] ; then
  resp_enckey=$(urlsafe_decode $(parse_header "$resp_header_file" "encrypt" "symmetricKey"))
  echo "response encrypted symmetric key: $resp_enckey"
  resp_aeskey=$(printf "$resp_enckey" | base64 -d | openssl rsautl -decrypt -pkcs -inkey "$privkey" | xxd -u -p)
  echo "response symmetric key: 0x$resp_aeskey"
  resp_content=$(printf "$respbody" | base64 -d | openssl enc -d -aes-128-ecb -K "$resp_aeskey")
else
  resp_content=$respbody
fi
echo "response content: $resp_content"
