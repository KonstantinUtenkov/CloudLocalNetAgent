#!/bin/bash

mkdir -p /mnt/host

pip install -r requirements.txt

uvicorn app.api:app --reload --host 0.0.0.0 --port 7190