#!/bin/bash

SERVER_HOST="0.0.0.0"
SERVER_PORT="7190"
NAME="cloudlocalnet-agent"


docker run \
    --network=host \
    --ipc=host \
    -t \
    --rm \
    --name $NAME-run \
    -p $SERVER_PORT:$SERVER_PORT \
    -e "SERVER_HOST=$SERVER_HOST" \
    -e "SERVER_PORT=$SERVER_PORT" \
    cloudlocalnet-agent:dev > out.log &