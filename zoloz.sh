#!/bin/bash 

show_help() {
  echo "
    SYNOPSIS
    $0 [-h|-?]
    $0 -c <client id> -P <merchant private key file> -p <zoloz public key file> [-a <api path>] [-H <api host>] [-d <request data or file>] [-e] [-i] [-k <aes128 key>] [-t <request time>] [-v|-vv]

    DESCRIPTION
    This is a utility script to call ZOLOZ API.

    OPTIONS
    -c <client id>                  Set client Id
    -P <merchant private key file>  Set merchant private key
    -p <zoloz public key file>      Set zoloz public key
    -H <API host>                   Set API host (default=https://sg-production-api.zoloz.com)
    -a <API path>                   Set API path (default=/api/v1/zoloz/authentication/test)
    -d <request data or data file>  Set request data or data file (set file by prepending '@' to file name)
                                    If not specified, will read request data from stdin
    -e                              Disable request encryption
    -i                              Ignore failure on verifying response signature
    -k <AES128 key>                 For debugging, use specified AES128 key to encrypt request instead of a randomly generated key
    -t <request time>               For debugging, use specified request time instead of current time
    -v                              More verbose
    -h                              Print this help

    EXAMPLES
    $0 -h
    $0 -c 2188000123456789 -P merchant_private_key.pem -p zoloz_public_key.pem
    $0 -c 2188000123456789 -P merchant_private_key.pem -p zoloz_public_key.pem -d '{\"foo\": \"bar\"}'
    $0 -c 2188000123456789 -P merchant_private_key.pem -p zoloz_public_key.pem -d @request_data.txt
"
}

parse_header() {
  local header_file=$1
  local header_key=$2
  local subkey=$3
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

error() {
  echo "$@" >&2
}

info() {
  if [ $VERBOSE -gt 0 ] ; then
    echo "$@" | sed 's/^/\> /' >&2
  fi
}

debug() {
  if [ $VERBOSE -gt 1 ] ; then
    echo "$@" | sed 's/^/\>\> /' >&2
  fi
}

# Initialize variables default:
VERBOSE=0
API_PATH='/api/v1/zoloz/authentication/test'
API_HOST='https://sg-production-api.zoloz.com'
REQ_TIME=$(date +%F'T'%T%z)
ENCRYPTION=1

if [ $# -eq 0 ]; then
  show_help
  exit 0
fi

OPTIND=1
while getopts ":?hvc:p:P:H:a:d:eik:t:" opt; do
  case "$opt" in
  h|\?)
    show_help
    exit 0
    ;;
  v)  VERBOSE=$(($VERBOSE + 1))
    ;;
  c)  CLIENT_ID=$OPTARG
    ;;
  P)  MERCHANT_PRIVATE_KEY_FILE=$OPTARG
    ;;
  p)  ZOLOZ_PUBLIC_KEY_FILE=$OPTARG
    ;;
  H)  API_HOST=$OPTARG
    ;;
  a)  API_PATH=$OPTARG
    ;;
  d)  REQ_DATA=$OPTARG
    ;;
  e)  ENCRYPTION=0
    ;;
  i)  SKIP_RESP_VERIFY=1
    ;;
  k)  REQ_AES_KEY=$OPTARG
    ;;
  t)  REQ_TIME=$OPTARG
    ;;
  :)
    error "$0: must supply an argument to -$OPTARG."
    exit 1
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
    error "zoloz private key is not specified."
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
info

info "client id: $CLIENT_ID"
info "merchant private key file: $MERCHANT_PRIVATE_KEY_FILE"
info "zoloz public key file: $ZOLOZ_PUBLIC_KEY_FILE"
info "api host: $API_HOST"
info "api path: $API_PATH"
info "request time: $REQ_TIME"
info

info "request data length: ${#REQ_DATA}"
debug "request data: '$REQ_DATA'"
info

info "encryption: $ENCRYPTION"
if [ "$ENCRYPTION" == "1" ] ; then
    if [ "$REQ_AES_KEY" == "" ] ; then
        export LC_CTYPE=C; REQ_AES_KEY=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 32 | head -n 1)
    fi
    info "aes128 key: 0x$REQ_AES_KEY"

    REQ_ENCRYPTED_AES_KEY=$(printf $REQ_AES_KEY | xxd -r -p | openssl rsautl -encrypt -pkcs -pubin -inkey "$ZOLOZ_PUBLIC_KEY_FILE" | base64)
    info "encrypted aes128 key: $REQ_ENCRYPTED_AES_KEY"

    URLENCODED_REQ_ENCRYPTED_AES_KEY=$(urlsafe_encode "$REQ_ENCRYPTED_AES_KEY")
    info "urlencoded encrypted aes128 key: $URLENCODED_REQ_ENCRYPTED_AES_KEY"

    REQ_BODY=$(printf "$REQ_DATA" | openssl enc -e -aes-128-ecb -K $REQ_AES_KEY | base64)
else
    REQ_BODY="$REQ_DATA"
fi
info

info "request body length: ${#REQ_BODY}"
debug "request body: '$REQ_BODY'"
info

REQ_SIGN_CONTENT="POST $API_PATH\n$CLIENT_ID.$REQ_TIME.$REQ_BODY"
debug "request content to be signed: '$REQ_SIGN_CONTENT'"
REQ_SIGNATURE=$(printf "$REQ_SIGN_CONTENT" | openssl dgst -sign $MERCHANT_PRIVATE_KEY_FILE -keyform PEM -sha256 | base64)
info "request signature: $REQ_SIGNATURE"
URLENCODED_REQ_SIGNATURE=$(urlsafe_encode $REQ_SIGNATURE)
info "urlencoded request signature: $URLENCODED_REQ_SIGNATURE"
info

RESP_HEADER_FILE=$(mktemp)
CURL_OPTIONS=(
    "HClient-Id: ${CLIENT_ID}" \
    "HRequest-Time: ${REQ_TIME}" \
    "HSignature: algorithm=RSA256, signature=${URLENCODED_REQ_SIGNATURE}" \
    "D${RESP_HEADER_FILE}" \
    "s"
)
if [ "$ENCRYPTION" == "1" ] ; then
  CURL_OPTIONS+=(
    "HContent-Type: text/plain; charset=UTF-8" \
    "HEncrypt: algorithm=RSA_AES, symmetricKey=${URLENCODED_REQ_ENCRYPTED_AES_KEY}" \
  )
else
  CURL_OPTIONS+=(
    "HContent-Type: application/json; charset=UTF-8" \
  )
fi
RESP_BODY=$(curl "${CURL_OPTIONS[@]/#/-}" --data-binary @<(printf "$REQ_BODY") "${API_HOST}${API_PATH}")

if [ "$?" != "0" ] ; then
  error "failed to request $API_HOST$API_PATH"
  exit 4
fi

info "temporary response header file: $RESP_HEADER_FILE"
RESP_HEADER=$(cat "$RESP_HEADER_FILE")
debug $"response header: $RESP_HEADER"
info

info "response body length: ${#RESP_BODY}"
debug "response body: '$RESP_BODY'"
info

if [ "$SKIP_RESP_VERIFY" == "1" ] ; then
  info "skip verifying response signature" >&2
else
  RESP_SIGNATURE=$(urlsafe_decode $(parse_header "$RESP_HEADER_FILE" "signature" "signature"))
  info "response signature: $RESP_SIGNATURE"
  RESP_TIME=$(parse_header "$RESP_HEADER_FILE" "response-time")
  info "response time: $RESP_TIME"
  RESP_SIGN_CONTENT="POST "$API_PATH"\n"$CLIENT_ID"."$RESP_TIME".""$RESP_BODY"
  debug "response content to be verified: '$RESP_SIGN_CONTENT'"

  RESP_VERIFY_RESULT=$(printf "$RESP_SIGN_CONTENT" | openssl dgst -verify "$ZOLOZ_PUBLIC_KEY_FILE" -keyform PEM -sha256 -signature <(printf $RESP_SIGNATURE | base64 -d))
  if [ "$RESP_VERIFY_RESULT" != "Verified OK" ] ; then
    error "verify response signature: $RESP_VERIFY_RESULT"
    exit 5
  fi
fi
info

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
info "response content length: ${#RESP_DATA}"
debug "response content: $RESP_DATA"
info

printf "$RESP_DATA"
