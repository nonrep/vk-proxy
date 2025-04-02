#!/bin/sh

mkdir certs/

openssl genrsa -out ca.key 2049
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=yngwie proxy CA"
openssl genrsa -out cert.key 2048
