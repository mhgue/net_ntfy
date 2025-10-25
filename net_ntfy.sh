#!/bin/bash
#
# Shell scrip to run net_ntfy.py in a virtual environment.
#

# Create virtual environment as hidden directory ".venv".
if [ ! -d ./.venv ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python net_ntfy.py "$@"
deactivate

#EOF