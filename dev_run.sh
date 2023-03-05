#!/bin/bash

apt -y update
apt -y install python3 python3-dev python3-pip syslog-ng

mkdir -p /mnt/host

pip install -r requirements.txt

uvicorn app.api:app --reload --host 0.0.0.0 --port 7190