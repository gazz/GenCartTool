# various utilities to interact with flashcart firmware
import sys
import os
from struct import pack
import logging
import serial

logging.basicConfig(format='%(asctime)s::%(levelname)s:: %(message)s',
    level=logging.INFO
    # level=logging.DEBUG
    )

def swap_bytes(input):
	output = []
	for i in range(0, len(input), 2):
		output.append(input[i +1])
		output.append(input[i])
	return output


def calc_page_crc(page_bytes, swap=True):
	if (swap):
		page_bytes = swap_bytes(page_bytes)

	logging.debug("calculating crc on {0} bytes".format(len(page_bytes)))
	CRC7_POLY = 0x91
	crc = 0
	for i in range(len(page_bytes)):
		crc = crc ^ page_bytes[i]
		for j in range(8):
			if crc & 1: crc = crc ^ CRC7_POLY
			crc = crc >> 1
		# print("{0}: {1:2X} {2}".format(i, page_bytes[i], crc))

	return crc

def serial_wait_on(ser, ack, error=None):
    # waits until serial gives back the expected ack
    while True:
        result = ser.readline().decode("utf-8").rstrip();
        if len(result) == 0: continue
        # sys.stdout.write("<=========: {0}, expecting: {1}".format(result, ack))
        logging.debug("<========= {0}".format(result))
        if error is not None and result.startswith(error):
        	return result
        if result == ack:
            return

def serial_write(ser, data):
    logging.debug("=========> {0}".format(data))
    ser.write(data)
    ser.flush()

def list_ports():
    import os
    import re

    if os.name == 'posix':
        from serial.tools.list_ports_posix import comports
    else:
        raise ImportError("Sorry: no implementation for your platform ('{}') available".format(os.name))

    iterator = sorted(comports(include_links=False))
    hits = 0

    # list them
    for n, (port, desc, hwid) in enumerate(iterator, 1):
        sys.stdout.write("{:20}\n".format(port))

def serial_wait_line(ser):
	while True:
		result = ser.readline().decode("utf-8").rstrip()
		if len(result) == 0: continue
		logging.debug("<========= {0}".format(result))
		if result.startswith("DEBUG:"): continue
		return result

def serial_wait_byteline(ser, bytes_to_read):
	logging.debug("Loading data into buf of size: ".format(bytes_to_read))
	bytes_read = 0;
	result = bytearray()
	while True:
		output = ser.read_until()
		result += output
		bytes_read += len(output)
		logging.debug("{0}/{1} bytes read".format(bytes_read, bytes_to_read))
		if bytes_read < bytes_to_read: continue
		break

	logging.debug("Raw bytes: {0}".format(result))
	logging.debug("Decoded bytes: {0}".format(result.hex()))
	# logging.debug("Cut bytes: {0}".format(result[:bytes_to_read]))
	return result[:bytes_to_read]
		

def get_serial(port, baud):
	logging.debug("Opening serial with port: {0}, baud: {1}".format(port, baud))
	ser = serial.Serial(port, baud, timeout=1)
	serial_wait_on(ser, "READY")

	serial_write(ser, b'PING\n')
	serial_wait_on(ser, "PONG")

	return ser

def debug_info(ser):
	serial_wait_on(ser, "READY")

	serial_write(ser, b'PING\n')
	serial_wait_on(ser, "PONG")
	logging.info("Got ping response from the device")

	serial_write(ser, b"READ_ROM_NAME\n")
	rom_name = serial_wait_line(ser)
	serial_write(ser, b"READ_ROM_SIZE\n")
	rom_size = serial_wait_line(ser)

	logging.info("Info:: EEPROM: {0} of size: {1}".format(rom_name, rom_size))

def read_page_crc(ser, address):
	serial_write(ser, b"READ_128_PAGE_CRC\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes(str(address) + "\n", "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return
	crc = serial_wait_line(ser)
	logging.debug("Page {0} CRC: {1}".format(address, crc))
	return crc

def read_page(ser, address):
	serial_write(ser, b"READ_128_PAGE\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes(str(address) + "\n", "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return
	rom_bytes = serial_wait_line(ser)
	logging.debug("EEPROM page at address {0}: {1}".format(address, rom_bytes.lower()))

	# read_page_crc(ser, address)

	# internal_crc = calc_page_crc(bytes.fromhex(rom_bytes));
	# logging.info("Local calc CRC: {0:X}".format(internal_crc))
	return bytes.fromhex(rom_bytes)

def read_128_pages(ser, address, num_pages):
	serial_write(ser, b"READ_128x128_PAGES\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes(str(address) + "\n", "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	serial_wait_on(ser, "AWAIT_PAGES_HEX")
	serial_write(ser, bytes(str("{0:x}".format(num_pages)) + "\n", "utf-8"))
	error = serial_wait_on(ser, "ACK_PAGES", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	buf_size = 128 * 2 * num_pages + 1
	rom_bytes = serial_wait_byteline(ser, buf_size)
	return [rom_bytes[:-1], rom_bytes[-1]]

def dumb_crc():
	data = "7a3b4c2d"
	data_bytes = bytes.fromhex(data) 
	expected_crc = "6A"
	bytes_len = int(len(data_bytes))
	logging.info("Bytes: {0} with len {1}, calculated bytelen: {2}".format(data_bytes, len(data_bytes), bytes_len))
	calculated_crc = calc_page_crc(data_bytes)
	logging.info("Dumb calc CRC: {0}, expected: {1}".format(calculated_crc, expected_crc))

def write_page(ser, address, page_bytes):

	logging.info("Writing page to address {0}".format(address))
	serial_write(ser, b"WRITE_128_PAGE\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes(address + "\n", "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	serial_write(ser, page_bytes)
	error = serial_wait_on(ser, "ACK_DATA_WRITE", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return
	logging.info("Page successfuly written to address {0}.".format(address))

	logging.info("Page {0} verification result: <TODO>.".format(address))

def write_test_page(ser, args):
	address = args[0]
	data = "0123456789abcdeffedcba9876543210" * 16
	write_page(ser, address, bytes(data, "utf-8"))

	read_page(ser, address)

def rom_read_test(ser, pages):
	# read all the pages and check crc for each one against local
	logging.info("Reading {0} pages...".format(pages))
	for i in range(0, pages, 128):
		[chunk_bytes, internal_crc] = read_128_pages(ser, "{0:x}".format(i * 128), min(pages, 128))
		internal_crc = "{0:X}".format(internal_crc)
		local_crc = "{0:X}".format(calc_page_crc(chunk_bytes, True))
		if local_crc != internal_crc:
			logging.error("CRC mismatch on page: {0} expected[on device] {1} got[this machine] {2}".format(i, internal_crc, local_crc))
			logging.debug("Raw bytes: {0}".format(chunk_bytes.hex()))
			return

		logging.info("{0}/{1} pages verified".format(i + 128, pages))

	logging.info("All pages read and validated")


def rom_read_test_slow(ser, pages):
	for i in range(pages):
		read_page(ser, "{0:x}".format(i * 128))
"""
def rom_read_test_OLD(ser):
	# read all the pages and check crc for each one against local
	pages_to_test = 1024

	for i in range(pages_to_test):
		address = i * 128;
		page_bytes = read_page(ser, address);
		internal_crc = read_page_crc(ser, address);
		local_crc = "{0:X}".format(calc_page_crc(page_bytes))

		if local_crc != internal_crc:
			logging.error("CRC mismatch on page: {0} expected {1} got {2}".format(i, internal_crc, local_crc))
			return

		# update status
		logging.info("{0}/{1} [{2:d}%] pages verified successfuly".format(i, pages_to_test, int(i / pages_to_test * 100)))

	logging.info("All {0} pages successfuly verified".format(pages_to_test))
"""

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='gencart util - A simple terminal program to interact with gencart eeprom/genesys via serial port on arduino.')

    parser.add_argument(
        'port',
        nargs='?',
        help='serial port name ("-" to show port list)')

    parser.add_argument(
        'action',
        nargs='?',
        help='action to perform, available actions: debug_info, read_page [address]')

    parser.add_argument(
        'action_args',
        nargs='?',
        help='action args')

    parser.add_argument(
        '--baud',
        nargs='?',
        help='set baud rate, default: %(default)s',
        # default=57600
        default=500000
        )

    parser.add_argument(
        '--listports',
        help='lists available serial ports',
        action="store_true")

    args = parser.parse_args()

    if args.listports == True:
        list_ports()
        return

    if args.action == "dumb_crc":
    	dumb_crc()
    	return

    ser = get_serial(args.port, args.baud)
    if args.action == "debug_info":
    	debug_info(ser)
    elif args.action == "read_page":
    	read_page(ser, args.action_args)
    elif args.action == "read_page_crc":
    	read_page_crc(ser, args.action_args)
    elif args.action == "write_test_page":
    	write_test_page(ser, args.action_args)
    elif args.action == "rom_read_test":
    	rom_read_test(ser, int(args.action_args))
    elif args.action == "rom_read_test_slow":
    	rom_read_test_slow(ser, int(args.action_args))
    else:
    	logging.debug("Invalid action: {0}".format(action))
    # flash_rom(args.port, args.baud, args.romfile)
    pass

if __name__ == '__main__':
    main()