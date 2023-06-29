#!/bin/bash

cat >kne/testbed.yml << EOF
username: admin
password: admin
topology: $PWD/kne/arista_magna.textproto
cli: $HOME/go/bin/kne
EOF
