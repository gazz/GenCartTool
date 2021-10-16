#!/bin/bash
while :
do
	python main.py /dev/cu.wchusbserial141310 verify_file test.bin
	sleep 1
done
