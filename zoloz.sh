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

# Initialize variables default:
API_PATH='/api/v1/zoloz/authentication/test'
API_HOST='https://sg-production-api.zoloz.com'
REQ_TIME=$(date +%F'T'%T%z)
ENCRYPTION=0
VERBOSE=0

OPTIND=1
while getopts ":?hvc:p:P:c:a:d:H:ek:t:l" opt; do
    case "$opt" in
    h|\?)
        show_help
        exit 0
        ;;
    v)  VERBOSE=1
        ;;
    t)  REQ_TIME=$OPTARG
        ;;
    c)  CLIENT_ID=$OPTARG
        ;;
    P)  MERCHANT_PRIVATE_KEY_FILE=$OPTARG
        ;;
    p)  ZOLOZ_PUBLIC_KEY_FILE=$OPTARG
        ;;
    a)  API_PATH=$OPTARG
        ;;
    H)  API_HOST=$OPTARG
        ;;
    e)  ENCRYPTION=1
        ;;
    k)  REQ_AES_KEY=$OPTARG
        ;;
    d)  REQ_DATA=$OPTARG
        ;;
    l)  SKIP_RESP_VERIFY=1
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

if [ "$CLIENT_ID" == "" ] ; then
    echo "client id is not specified." >&2
    exit -1
fi

if [ "$MERCHANT_PRIVATE_KEY_FILE" == "" ] ; then
    echo "merchant private key is not specified." >&2
    exit -1
fi

if [ "$ZOLOZ_PUBLIC_KEY_FILE" == "" ] ; then
    echo "zoloz private key is not specified." >&2
    exit -1
fi

if [[ "$REQ_DATA" == "" ]] ; then
  read REQ_DATA
else
  if [[ "$REQ_DATA" == @* ]] ; then
    REQ_INPUT_FILE=${REQ_DATA:1}
    REQ_DATA=$(cat "$REQ_INPUT_FILE")
  fi
fi

echo "client id: $CLIENT_ID"
echo "merchant private key file: $MERCHANT_PRIVATE_KEY_FILE"
echo "zoloz public key file: $ZOLOZ_PUBLIC_KEY_FILE"
echo "api host: $API_HOST"
echo "api path: $API_PATH"
echo "request time: $REQ_TIME"

echo "encryption: $ENCRYPTION"
if [ "$ENCRYPTION" == "1" ] ; then
    if [ "$REQ_AES_KEY" == "" ] ; then
        export LC_CTYPE=C; REQ_AES_KEY=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 32 | head -n 1)
    fi
    echo "aes128 key: 0x$REQ_AES_KEY"

    REQ_ENCRYPTED_AES_KEY=$(printf $REQ_AES_KEY | xxd -r -p | openssl rsautl -encrypt -pkcs -pubin -inkey "$ZOLOZ_PUBLIC_KEY_FILE" | base64)
    echo "encrypted aes128 key: $REQ_ENCRYPTED_AES_KEY"

    REQ_BODY=$(printf "$REQ_DATA" | openssl enc -e -aes-128-ecb -K $REQ_AES_KEY | base64)
else
    REQ_BODY="$REQ_DATA"
fi
echo "request body: '$REQ_BODY'"

REQ_SIGN_CONTENT="POST $API_PATH\n$CLIENT_ID.$REQ_TIME.$REQ_BODY"
echo "request content to be signed: '$REQ_SIGN_CONTENT'"

REQ_SIGNATURE=$(urlsafe_encode $(printf "$REQ_SIGN_CONTENT" | openssl dgst -sign $MERCHANT_PRIVATE_KEY_FILE -keyform PEM -sha256 | base64))
echo "request signature: $REQ_SIGNATURE"

RESP_HEADER_FILE=$(mktemp)
echo "temporary response header file: $RESP_HEADER_FILE"

if [ "$ENCRYPTION" == "1" ] 
then
  RESP_BODY=$(curl \
    -H "Content-Type: text/plain" \
    -H "Client-Id: $CLIENT_ID" \
    -H "Request-Time: $REQ_TIME" \
    -H "Signature: algorithm=RSA256, signature=$REQ_SIGNATURE" \
    -H "Encrypt: algorithm=RSA_AES, symmetricKey=$(urlsafe_encode $REQ_ENCRYPTED_AES_KEY)" \
    -d "$REQ_BODY" \
    -s -D "$RESP_HEADER_FILE" \
    "$API_HOST$API_PATH")
else
  RESP_BODY=$(curl \
    -H "Content-Type: application/json; charset=UTF-8" \
    -H "Client-Id: $CLIENT_ID" \
    -H "Request-Time: $REQ_TIME" \
    -H "Signature: algorithm=RSA256, signature=$REQ_SIGNATURE" \
    --data-binary @<(printf "$REQ_BODY") \
    -s -D "$RESP_HEADER_FILE" \
    "$API_HOST$API_PATH")
fi

echo "response body: '$RESP_BODY'"
RESP_HEADER=$(cat "$RESP_HEADER_FILE")
echo $"response header: \n$RESP_HEADER"
RESP_SIGNATURE=$(urlsafe_decode $(parse_header "$RESP_HEADER_FILE" "signature" "signature"))
echo "response signature: $RESP_SIGNATURE"
RESP_TIME=$(parse_header "$RESP_HEADER_FILE" "response-time")
echo "response time: $RESP_TIME"

RESP_SIGN_CONTENT="POST "$API_PATH"\n"$CLIENT_ID"."$RESP_TIME".""$RESP_BODY"
echo "response content to be verified: '$RESP_SIGN_CONTENT'"

if [ "$SKIP_RESP_VERIFY" == "1" ] ; then
  echo "skip verifying response signature" >&2
else
  RESP_VERIFY_RESULT=$(printf "$RESP_SIGN_CONTENT" | openssl dgst -verify "$ZOLOZ_PUBLIC_KEY_FILE" -keyform PEM -sha256 -signature <(printf $RESP_SIGNATURE | base64 -d))
  echo "verify response signature: $RESP_VERIFY_RESULT"
  if [ "$RESP_VERIFY_RESULT" != "Verified OK" ] ; then
    exit -1
  fi
fi

RESP_CONTENT_TYPE=$(parse_header "$RESP_HEADER_FILE" "content-type")
echo "response content type: $RESP_CONTENT_TYPE"
if [[ "$RESP_CONTENT_TYPE" == *"text/plain"* ]] ; then
  RESP_ENCRYPTED_AES_KEY=$(urlsafe_decode $(parse_header "$RESP_HEADER_FILE" "encrypt" "symmetricKey"))
  echo "response encrypted symmetric key: $RESP_ENCRYPTED_AES_KEY"
  RESP_AES_KEY=$(printf "$RESP_ENCRYPTED_AES_KEY" | base64 -d | openssl rsautl -decrypt -pkcs -inkey "$MERCHANT_PRIVATE_KEY_FILE" | xxd -u -p)
  echo "response symmetric key: 0x$RESP_AES_KEY"
  RESP_DATA=$(printf "$RESP_BODY" | base64 -d | openssl enc -d -aes-128-ecb -K "$RESP_AES_KEY")
else
  RESP_DATA=$RESP_BODY
fi
echo "response content: $RESP_DATA"
