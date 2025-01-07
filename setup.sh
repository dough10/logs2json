#!/bin/bash
set -e

sudo apt install python3 python3-pip python3-venv -y

python3 -m venv .venv

.venv/bin/pip install -r requirments.txt

sudo ln -sfv /media/dough10/scripts/logs2json/logs2json.sh /usr/local/bin/logs2json