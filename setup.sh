#!/usr/bin/env bash

echo "Creating virtual environment..."
python3.9 -m venv env
echo "Virtual environment created."
source env/bin/activate
echo "Installing dependencies..."
python -m pip install -r requirements.txt
printf "Dependencies installed.\nTo enter the virtual environment, type 'source env/bin/activate'\nThen, you can run the Macaron Explorer with \'python macaron_shell.py\'.\nTo exit the virtual environment, type 'deactivate'.\n\n"