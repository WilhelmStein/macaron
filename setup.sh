#!/usr/bin/env bash

echo "Creating virtual environment..."
python3 -m venv env
echo "Virtual environment created.\n"
source env/bin/activate
echo "Installing dependencies..."
pip3 install -r requirements.txt
printf "Dependencies installed.\nTo enter the virtual environment, type 'source env/bin/activate'\nThen, you can run the Macaron Explorer with \'python3 macaron_shell.py\'.\nTo exit the virtual environment, type 'deactivate'.\n\n"