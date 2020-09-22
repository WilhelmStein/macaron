#!/usr/bin/env bash

echo "Creating virtual environment..."
python3 -m venv env
echo "Virtual environment created."
source env/bin/activate
echo "Installing dependencies..."
pip3 install -r requirements.txt
echo "Dependencies installed."
deactivate