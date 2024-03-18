#!/usr/bin/bash

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout localhost.key \
  -out localhost.crt \
  -config localhost.conf \
  -passin pass:

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout ca.key \
  -out ca.crt \
  -config ca.conf \
  -passin pass:

cp config.toml.in docker-compose/aas/config.toml
cp cdh-config.toml docker-compose/guest-components/cdh-config.toml

replace_section() {
    local replacement_file=$1
    local placeholder=$2
    local file_to_modify=$3

    content=$(sed 's:[:\/&]:\\&:g;s/$/\\n/' $replacement_file | tr -d '\n')
    sed -i "s/${placeholder}/${content}/g" "$file_to_modify"
}

replace_section localhost.key @HTTPS_PRIVATE_KEY@ docker-compose/aas/config.toml
replace_section localhost.crt @HTTPS_CERT@ docker-compose/aas/config.toml
replace_section ca.crt @CLIENT_ROOT_CA_CERT@ docker-compose/aas/config.toml
replace_section ca.key @CLIENT_CA_PRIVATE_KEY@ docker-compose/aas/config.toml
replace_section ca.crt @CLIENT_CA_CERT@ docker-compose/aas/config.toml
replace_section localhost.crt @KBS_HTTPS_CERT@ docker-compose/guest-components/cdh-config.toml