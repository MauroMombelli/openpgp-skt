#!/bin/bash

make

export GNUPGHOME=/tmp/tmpKey

if [ ! -d $GNUPGHOME ] 
then
    mkdir -p $GNUPGHOME
    gpg --batch --pinentry-mode=loopback --passphrase-fd=4 4<<<'' --quick-gen-key 'test user <test@example.org>'
fi

./testGpg

gpgconf --kill all
