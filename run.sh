#!/bin/bash
rom=$1
echo "Loading ${rom}"
python main.py write_file "$1"
python main.py genesis_reset