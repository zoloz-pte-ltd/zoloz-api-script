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
    echo -n "$header_val"
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
    echo -n "$subval"
  fi
}

error() {
  local content=${1//+/ }
  echo "$content" >&2
}

info() {
  local content=${1//+/ }
  if [ $VERBOSE -gt 0 ] ; then
    echo "$content" | sed 's/^/\> /' >&2
  fi
}

debug() {
  local content=${1//+/ }
  if [ $VERBOSE -gt 1 ] ; then
    echo "$content" >&2
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
    v)  VERBOSE=$(($VERBOSE + 1))
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
      error "$0: must supply an argument to -$OPTARG."
      exit 1
      ;;
    ?)
      error "invalid option: -${OPTARG}."
      exit 2
      ;;
    esac
done
shift $((OPTIND-1))
[ "${1:-}" = "--" ] && shift

if [ "$CLIENT_ID" == "" ] ; then
    error "client id is not specified."
    exit 3
fi

if [ "$MERCHANT_PRIVATE_KEY_FILE" == "" ] ; then
    error "merchant private key is not specified."
    exit 3
fi

if [ "$ZOLOZ_PUBLIC_KEY_FILE" == "" ] ; then
    echo "zoloz private key is not specified." >&2
    exit 3
fi

if [[ "$REQ_DATA" == "" ]] ; then
  read REQ_DATA
else
  if [[ "$REQ_DATA" == @* ]] ; then
    REQ_INPUT_FILE=${REQ_DATA:1}
    REQ_DATA=$(cat "$REQ_INPUT_FILE")
  fi
fi

info "verbose: $VERBOSE"
info "client id: $CLIENT_ID"
info "merchant private key file: $MERCHANT_PRIVATE_KEY_FILE"
info "zoloz public key file: $ZOLOZ_PUBLIC_KEY_FILE"
info "api host: $API_HOST"
info "api path: $API_PATH"
info "request time: $REQ_TIME"

info "encryption: $ENCRYPTION"
if [ "$ENCRYPTION" == "1" ] ; then
    if [ "$REQ_AES_KEY" == "" ] ; then
        export LC_CTYPE=C; REQ_AES_KEY=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 32 | head -n 1)
    fi
    info "aes128 key: 0x$REQ_AES_KEY"

    REQ_ENCRYPTED_AES_KEY=$(printf $REQ_AES_KEY | xxd -r -p | openssl rsautl -encrypt -pkcs -pubin -inkey "$ZOLOZ_PUBLIC_KEY_FILE" | base64)
    info "encrypted aes128 key: $REQ_ENCRYPTED_AES_KEY"

    REQ_BODY=$(printf "$REQ_DATA" | openssl enc -e -aes-128-ecb -K $REQ_AES_KEY | base64)
else
    REQ_BODY="$REQ_DATA"
fi
info "request body: '$REQ_BODY'"

REQ_SIGN_CONTENT="POST $API_PATH\n$CLIENT_ID.$REQ_TIME.$REQ_BODY"
info "request content to be signed: '$REQ_SIGN_CONTENT'"

REQ_SIGNATURE=$(urlsafe_encode $(printf "$REQ_SIGN_CONTENT" | openssl dgst -sign $MERCHANT_PRIVATE_KEY_FILE -keyform PEM -sha256 | base64))
info "request signature: $REQ_SIGNATURE"

RESP_HEADER_FILE=$(mktemp)
info "temporary response header file: $RESP_HEADER_FILE"

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

info "response body: '$RESP_BODY'"
RESP_HEADER=$(cat "$RESP_HEADER_FILE")
info $"response header: \n$RESP_HEADER"
RESP_SIGNATURE=$(urlsafe_decode $(parse_header "$RESP_HEADER_FILE" "signature" "signature"))
info "response signature: $RESP_SIGNATURE"
RESP_TIME=$(parse_header "$RESP_HEADER_FILE" "response-time")
info "response time: $RESP_TIME"

RESP_SIGN_CONTENT="POST "$API_PATH"\n"$CLIENT_ID"."$RESP_TIME".""$RESP_BODY"
info "response content to be verified: '$RESP_SIGN_CONTENT'"

if [ "$SKIP_RESP_VERIFY" == "1" ] ; then
  info "skip verifying response signature" >&2
else
  RESP_VERIFY_RESULT=$(printf "$RESP_SIGN_CONTENT" | openssl dgst -verify "$ZOLOZ_PUBLIC_KEY_FILE" -keyform PEM -sha256 -signature <(printf $RESP_SIGNATURE | base64 -d))
  if [ "$RESP_VERIFY_RESULT" != "Verified OK" ] ; then
    error "verify response signature: $RESP_VERIFY_RESULT"
    exit 4
  fi
fi

RESP_CONTENT_TYPE=$(parse_header "$RESP_HEADER_FILE" "content-type")
info "response content type: '$RESP_CONTENT_TYPE'"
if [[ "$RESP_CONTENT_TYPE" == *"text/plain"* ]] ; then
  RESP_ENCRYPTED_AES_KEY=$(urlsafe_decode $(parse_header "$RESP_HEADER_FILE" "encrypt" "symmetricKey"))
  info "response encrypted symmetric key: $RESP_ENCRYPTED_AES_KEY"
  RESP_AES_KEY=$(printf "$RESP_ENCRYPTED_AES_KEY" | base64 -d | openssl rsautl -decrypt -pkcs -inkey "$MERCHANT_PRIVATE_KEY_FILE" | xxd -u -p)
  info "response symmetric key: 0x$RESP_AES_KEY"
  RESP_DATA=$(printf "$RESP_BODY" | base64 -d | openssl enc -d -aes-128-ecb -K "$RESP_AES_KEY")
else
  RESP_DATA=$RESP_BODY
fi
info "response content: $RESP_DATA"

printf "$RESP_DATA"
