# various utilities to interact with flashcart firmware
import sys
import os
from struct import pack
import logging
import serial
import time
import diff

# DEFAULT_BAUD=1000000
DEFAULT_BAUD=500000
# DEFAULT_BAUD=115200
# DEFAULT_BAUD=19200

OUTPUT_READ_BYTES = False
# OUTPUT_READ_BYTES = True

FULL_DEBUG = False
# FULL_DEBUG = True

DEVICE_LOG = FULL_DEBUG or False
DEVICE_DEBUG = FULL_DEBUG or False


logging.basicConfig(format='%(asctime)s::%(levelname)s:: %(message)s',
    # level=logging.INFO
    level= logging.DEBUG if DEVICE_LOG else logging.INFO
    )


def get_serial(port, baud):
	logging.debug("Opening serial with port: {0}, baud: {1}".format(port, baud))
	ser = serial.Serial(port, baud, timeout=1)
	# ser.xonxoff = True
	logging.debug("Serial open, XONXOFF flow control: {0}".format(ser.xonxoff))
	serial_wait_on(ser, "READY")

	if not DEVICE_DEBUG:
		serial_write(ser, b'DEBUG_OFF\n')

	serial_write(ser, b'PING\n')
	serial_wait_on(ser, "PONG")

	return ser


def swap_bytes(input):
	output = []
	for i in range(0, len(input), 2):
		output.append(input[i +1])
		output.append(input[i])
	return output


def calc_page_crc(page_bytes, swap=True, start_crc=0):
	if (swap):
		page_bytes = swap_bytes(page_bytes)

	logging.debug("calculating crc on {0} bytes".format(len(page_bytes)))
	CRC7_POLY = 0x91
	crc = start_crc
	for i in range(len(page_bytes)):
		crc = crc ^ page_bytes[i]
		for j in range(8):
			if crc & 1: crc = crc ^ CRC7_POLY
			crc = crc >> 1
		# if i % 128 == 0:
		# 	logging.debug("{0}: {1:X} {2}".format(i, page_bytes[i], crc))

	return crc

def serial_wait_on(ser, ack, error=None, timeout=3):
    # waits until serial gives back the expected ack
    start = time.time()
    while True:
        result = ser.readline().decode("utf-8").rstrip();
        if len(result) == 0: 
	        if time.time() > start + timeout:
	        	raise Exception("Timed out while waiting for device to acknowledge request {0}".format(ack))
        	continue
        # sys.stdout.write("<=========: {0}, expecting: {1}".format(result, ack))
        logging.debug("<========= {0}".format(result))
        if error is not None and result.startswith(error):
            return result
        # logging.debug("got '{0}' expected '{1}', got match: {2}".format(result, ack, ack == result))
        if result == ack:
            return

def serial_write(ser, data):
    logging.debug("=========> {0}".format(data))
    # send 64 bytes at a time & add a little wait in between as a hack to avoid buffer overrun, arduino serial does not have any flow control 
    chunk_size = 128
    for chunk in [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]:
    	size_written = ser.write(chunk)
    	# logging.debug("Wrote chunk of size: {0}, chunk: {1}".format(size_written, chunk))
    	time.sleep(.01)

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
    ports = []
    for n, (port, desc, hwid) in enumerate(iterator, 1):
    	ports.append(port)
        # sys.stdout.write("{:20}\n".format(port))

    return ports 

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
		logging.debug("{0}/{1} bytes read".format(bytes_read, bytes_to_read + 2))
		if bytes_read < bytes_to_read: continue
		break

	if OUTPUT_READ_BYTES:
		logging.debug("Raw bytes: {0}".format(result))
		logging.debug("Decoded bytes: {0}".format(result.hex()))
	# logging.debug("Cut bytes: {0}".format(result[:bytes_to_read]))
	return result[:bytes_to_read]
		


def debug_info(ser):
	# serial_wait_on(ser, "READY")

	serial_write(ser, b'PING\n')
	serial_wait_on(ser, "PONG")
	logging.info("Got ping response from the device")

	serial_write(ser, b"READ_ROM_NAME\n")
	rom_name = serial_wait_line(ser)
	# serial_write(ser, b"READ_ROM_SIZE\n")
	# rom_size = serial_wait_line(ser)

	rom_size = 0;
	logging.info("Info:: EEPROM: {0} of size: {1}".format(rom_name, rom_size))

def read_page_crc(ser, page):
	serial_write(ser, b"READ_128_PAGE_CRC\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	page_address = int(page) * 128
	logging.debug("calculated page address: {0}".format(page_address))
	serial_write(ser, bytes(str(page_address) + "\n", "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return
	crc = serial_wait_line(ser)
	logging.debug("Page {0} at address 0x{1} CRC: {2}".format(page, page_address, crc))
	return crc

def read_page(ser, page, cart=False):
	serial_write(ser, b"READ_128_PAGE\n" if cart == False else b"CART_READ_128_PAGE\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	page_address = int(page) * 128
	logging.debug("calculated page address: {0}".format(page_address))
	serial_write(ser, bytes("{0:x}".format(page_address) + "\n", "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	error = serial_wait_on(ser, "DATA_BEGIN", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	rom_bytes = serial_wait_line(ser)
	logging.debug("EEPROM page {0} at address 0x{1:x}: {2}".format(page, page_address, rom_bytes.lower()))
	return bytes.fromhex(rom_bytes)

def read_128_pages(ser, address, num_pages, cart=False):
	serial_write(ser, b"READ_128x128_PAGES\n" if not cart else b"CART_READ_128x128_PAGES\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes("{0:x}\n".format(address), "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	serial_wait_on(ser, "AWAIT_PAGES_HEX")
	serial_write(ser, bytes("{0:x}\n".format(num_pages), "utf-8"))
	error = serial_wait_on(ser, "ACK_PAGES", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	error = serial_wait_on(ser, "DATA_BEGIN", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	buf_size = 128 * 2 * num_pages + 1
	rom_bytes = serial_wait_byteline(ser, buf_size)
	return [rom_bytes[:-1], rom_bytes[-1]]

def read_pages(ser, start_page, num_pages, cart=False):
	total_res = bytes()
	pages_per_read = 1
	logging.info("Reading pages from start page: {0}, num pages: {1}, pages per read: {2} cart?: {3}".format(start_page, num_pages, pages_per_read, cart))
	for p in range(start_page, start_page + num_pages, pages_per_read):
		res = read_128_pages(ser, p * 128, pages_per_read, cart)
		total_res += res[0]

	return total_res

def dumb_crc():
	data = "7a3b4c2d"
	data_bytes = bytes.fromhex(data) 
	expected_crc = "6A"
	bytes_len = int(len(data_bytes))
	logging.info("Bytes: {0} with len {1}, calculated bytelen: {2}".format(data_bytes, len(data_bytes), bytes_len))
	calculated_crc = calc_page_crc(data_bytes)
	logging.info("Dumb calc CRC: {0}, expected: {1}".format(calculated_crc, expected_crc))

def write_page(ser, address, page_bytes):
	logging.debug("Writing page to address {0}".format(address))
	serial_write(ser, b"WRITE_128_PAGE\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes("{0:x}\n".format(int(address)), "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	error = serial_wait_on(ser, "AWAIT_DATA_HEX", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	serial_write(ser, bytes(page_bytes.hex(), "utf-8"))
	logging.debug("Waiting for data write acknowldege")
	error = serial_wait_on(ser, "ACK_DATA_WRITE", "ERR", timeout=30)
	if error:
		logging.error("Error: {0}".format(error))
		return
	logging.debug("Got data write acknowldege")

	device_crc = int(serial_wait_line(ser), 16)
	input_data_crc = calc_page_crc(page_bytes)
	# logging.debug("Page bytes: {0}".format(page_bytes))

	logging.debug("Page {0} CRC on device: {1}, sent data crc: {2}.".format(int(address/128), device_crc, input_data_crc))
	if device_crc != input_data_crc:
		logging.warning("Page {0} write failed, CRC mismatch, device: {1}, sent data crc: {2}".format(int(address/128), device_crc, input_data_crc))
		return False

	return True

def write_pages(ser, address, data):
	num_pages = int(len(data)/256)
	logging.debug("Writing {0} pages ({1} bytes) to address {2}".format(num_pages, len(data), address))

	serial_write(ser, b"WRITE_128X_PAGES\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes("{0:x}\n".format(int(address)), "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	serial_wait_on(ser, "AWAIT_PAGES_HEX")
	serial_write(ser, bytes("{0:x}\n".format(num_pages), "utf-8"))
	error = serial_wait_on(ser, "ACK_PAGES", "ERR")
	if error:
		logging.error("Error: {0}".format(error))

	crc = 0
	pages_per_write = 1
	for page in range(0, num_pages, pages_per_write):
		error = serial_wait_on(ser, "AWAIT_DATA_HEX", "ERR")
		logging.debug("----------------------------------------------------------")

		if error:
			logging.error("Error: {0}".format(error))
			return
		bytes_per_write = 256 * pages_per_write
		page_bytes = data[:bytes_per_write]
		# pad bytes to fill in the page with 0
		if (len(page_bytes) < bytes_per_write):
			pad_bytes = bytes_per_write - len(page_bytes)
			page_bytes += b"\xff" * pad_bytes
			# logging.debug("Padding chunk write with {0} bytes: {1}".format(pad_bytes, page_bytes))


		serial_write(ser, bytes(page_bytes.hex(), "utf-8"))
		data = data[256 * pages_per_write:]

		error = serial_wait_on(ser, "ACK_DATA", "ERR")
		if error:
			logging.error("Error: {0}".format(error))
			return
		
		logging.info("Page {0}/{1} successfuly written [{2:.2f}%]"
			.format(page + 1, num_pages, ((page + 1)/num_pages * 100)))

		crc = calc_page_crc(page_bytes, start_crc=crc)
		logging.debug("Current local crc: {0:x}".format(crc))


	logging.debug("Waiting for data write acknowldege")
	error = serial_wait_on(ser, "ACK_DATA_WRITE", "ERR", timeout=30)
	if error:
		logging.error("Error: {0}".format(error))
		return
	logging.debug("Got data write acknowldege")

	device_crc = int(serial_wait_line(ser), 16)
	# device_crc = serial_wait_line(ser)
	input_data_crc = crc

	logging.debug("CRC on device: {0}, sent data crc: {1}.".format(device_crc, input_data_crc))
	if device_crc != input_data_crc:
		logging.warning("Multi page write failed, CRC mismatch, device: {0}, sent data crc: {1}".format(device_crc, input_data_crc))
		return False

	return True


def write_test_page(ser, args):
	pages = int(args if args is not None else 1)
	data = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10' * 16
	logging.info("Writing {0} test pages with data: {1}".format(pages, data))
	for i in range(pages):
		write_page(ser, i * 128, data)

def write_fill_page(ser, page, fillhex="00"):
	data = bytes.fromhex("{0:02x}".format(int(fillhex[0:2], 16)) * 16 * 16)
	write_page(ser, page * 128, data)

def write_file_slow(ser, filename):
	rom_contents = []
	start_address = 0
	try:
		with open(filename, mode="rb") as f:
			rom_contents = f.read()
			rom_size = len(rom_contents)
			logging.info("Writing {0} Bytes to file {1}".format(rom_size, filename));

			total_pages = int(rom_size / 256)
			page = 0
			while True:
				bytes_to_write = rom_contents[:256]
				if len(bytes_to_write) > 0:
					rom_contents = rom_contents[256:]
					logging.debug("writing page {0} with bytes: {1}".format(page, bytes_to_write.hex()))

					page_address = page * 128
					# retry block
					retries = 3
					retry = 1
					while True:
						result = write_page(ser, page_address, bytes_to_write)
						if result:
							break

						elif retry < retries:
							logging.warning("Retry: {0}".format(retry))
							retry += 1
							continue
						else:
							raise Exception("Error writing page {0} after {1} retries".format(page, retries))

					logging.info("Page {0}/{1} successfuly written to address {2} [{3:.2f}%]"
						.format(page + 1, total_pages, page_address, ((page + 1)/total_pages * 100)))

					page += 1
				else:
					break;

	except Exception as err:
		logging.error("Got error: {0}".format(err))
		return None

	logging.info("{0} Bytes written from file {1}".format(rom_size, filename))

def write_file_fast(ser, filename):
	rom_contents = []
	start_address = 0
	try:
		with open(filename, mode="rb") as f:
			rom_contents = f.read()
			rom_size = len(rom_contents)
			logging.info("Writing {0} bytes to rom from file {1}".format(rom_size, filename));

			result = write_pages(ser, 0, rom_contents)

	except Exception as err:
		logging.error("Got error: {0}".format(err))
		return None

	logging.info("{0} Bytes written from file {1}".format(rom_size, filename))

def write_file(ser, filename):
	# write_file_fast(ser, filename)
	write_file_fast(ser, filename)


def rom_read_test_slow(ser, pages):
	logging.info("Reading {0} pages...".format(pages))
	for i in range(pages):
		read_page(ser, "{0:x}".format(i * 128))
		logging.info("{0}/{1} pages verified".format(i+1, pages))

	logging.info("All pages read and validated")

def rom_read_test(ser, pages):
	# read all the pages and check crc for each one against local
	logging.info("Reading a total of {0} pages...".format(pages))
	for i in range(0, pages, 128):
		# max(i, min(pages % 128, 128))
		pages_to_read = 128 if i < pages - 128 else pages % 128

		logging.info("Chunked read of {0} pages".format(pages_to_read))
		[chunk_bytes, internal_crc] = read_128_pages(ser, "{0:x}".format(i * 128), pages_to_read)
		internal_crc = "{0:X}".format(internal_crc)
		local_crc = "{0:X}".format(calc_page_crc(chunk_bytes, True))
		if local_crc != internal_crc:
			logging.error("CRC mismatch on page: {0} expected[on device] {1} got[this machine] {2}".format(i, internal_crc, local_crc))
			logging.debug("Raw bytes: {0}".format(chunk_bytes.hex()))
			return

		logging.info("{0}/{1} pages verified".format(pages, pages))

	logging.info("All pages read and validated")

def mismatch_index(a, b):
	index = 0;
	for i in range(len(a)):
		if a[i] != b[i]:
			logging.warning("{0} is not {1} res: {2}, a: {3}, b: {4}".format(a[i], b[i], a[i] == b[i], a[i-5:i+5], b[i-5:i+5]))
			return index
	return -1


def verify_rom(ser, filename, cart=False):
	# verifies that EEPROM has the contents of the file
	logging.info("Verifying file {0} contents against EEPROM on device".format(filename))
	try:
		with open(filename, mode="rb") as f:
			rom_contents = f.read()
			rom_size = len(rom_contents)
			logging.info("Verifying {0} bytes from file {1}".format(rom_size, filename));

			total_pages = int(rom_size / 256)

			for start_page in range(0, total_pages, 128):
				pages_to_read = 128
				if start_page + 128 > total_pages:
					pages_to_read = total_pages - start_page

				logging.info("Verifying {0} bytes at address {1}...".format(pages_to_read * 256, start_page * 128));
				[chunk_bytes, device_crc] = read_128_pages(ser, start_page * 128, pages_to_read, cart)
				verification_bytes = rom_contents[:pages_to_read * 256]
				rom_contents = rom_contents[pages_to_read * 256:]
				file_crc = calc_page_crc(verification_bytes)
	

				# logging.debug("Device CRC: {0}, File CRC: {1}".format(device_crc, file_crc))

				if file_crc != device_crc:
					fail_index = max(min(mismatch_index(chunk_bytes, verification_bytes), 0), len(verification_bytes))
					logging.error("Fail CRC at index {0}".format(fail_index))
					logging.error("Page failed CRC: EEPROM: {0}".format(hex_format(chunk_bytes[fail_index - 10: fail_index + 10].hex())))
					logging.error("Page failed CRC: BIN: {0}".format(hex_format(verification_bytes[fail_index - 10: fail_index + 10].hex())))

					# logging.debug("Diff:\n {0}".format(diff.show_diff(chunk_bytes, verification_bytes)))
					diff.show_diff(chunk_bytes, verification_bytes, address_offset=start_page * 256)
					# logging.debug("File Bytes: {1}\nDevice Bytes: {0}".format(hex_format(chunk_bytes.hex()), hex_format(verification_bytes.hex())))
					raise Exception("CRC mismatch at page {0}, device CRC: {1}, file CRC: {2}".format(start_page, device_crc, file_crc))
				verified_percentage = int(min(start_page + 128, total_pages) / total_pages * 100);
				logging.info("SUCCESS Verifying {0} bytes at address {1} [{2}%]".format(pages_to_read * 256, start_page * 128, verified_percentage));

	except Exception as err:
		logging.error("Got error: {0}".format(err))
		raise err
		return None

	logging.info("{0} Bytes verified against file {1}".format(rom_size, filename))


def dump_rom(ser, filename, num_bytes):
	# verifies that EEPROM has the contents of the file
	logging.info("Dumping rom into file {0} with the contents from EEPROM on device".format(filename))
	try:
		with open(filename, mode="wb") as wf:
			# write bin file from rom based on the size returned by the gencart
			# get rom size

			serial_write(ser, b"READ_ROM_NAME\n")
			rom_name = serial_wait_line(ser)
			serial_write(ser, b"READ_ROM_SIZE\n")
			rom_size = int(serial_wait_line(ser), 16)

			bytes_to_dump = int(num_bytes) if num_bytes > 0 else rom_size
			logging.info("Info:: EEPROM: {0} of size: {1}, reading {2} [{3}] bytes".format(rom_name, rom_size, bytes_to_dump, num_bytes))


			page_size_in_words = 128
			pages_per_fetch = 128
			for page_start_address in range(0, int(bytes_to_dump/2), pages_per_fetch * page_size_in_words):
				[chunk_bytes, device_crc] = read_128_pages(ser, page_start_address, pages_per_fetch)
				wf.write(chunk_bytes)

				bytes_dumped = (page_start_address + pages_per_fetch * page_size_in_words) * 2
				logging.info("Dumped {0}/{1} [{2:.2f}%] bytes".format(bytes_dumped,
					bytes_to_dump, bytes_dumped / bytes_to_dump * 100))

			# total_pages = int(rom_size / 256)

			# for start_page in range(0, total_pages, 128):
			# 	pages_to_read = 128 if start_page < total_pages - 128 else total_pages % 128
			# 	logging.info("Verifying {0} bytes at address {1}".format(pages_to_read * 256, start_page * 128));
			# 	[chunk_bytes, device_crc] = read_128_pages(ser, "{0:x}".format(start_page * 128), pages_to_read)
			# 	verification_bytes = rom_contents[:pages_to_read * 256]
			# 	rom_contents = rom_contents[pages_to_read * 256:]
			# 	file_crc = calc_page_crc(verification_bytes)
	

			# 	# logging.debug("Device Bytes: {0}\nFile Bytes: {1}".format(chunk_bytes, verification_bytes))
			# 	# logging.debug("Device CRC: {0}, File CRC: {1}".format(device_crc, file_crc))

			# 	if file_crc != device_crc:
			# 		raise Exception("CRC mismatch at page {0}, device CRC: {1}, file CRC: {2}".format(start_page, device_crc, file_crc))
			# 	logging.info("SUCCESS Verifying {0} bytes at address {1}".format(pages_to_read * 256, start_page * 128));

	except Exception as err:
		logging.error("Got error: {0}".format(err))
		raise err
		return None

	logging.info("{0} Bytes dumped to file {1}".format(bytes_to_dump, filename))

def generate_test_rom(filename, pages):
	try:
		pages = max(1, pages)
		bytes_written = 0
		import random
		bytes_to_generate = pages * 256
		logging.info("Generating file with {0} pages of {1} bytes".format(pages, bytes_to_generate))
		with open(filename, mode="bw") as f:
			for val in range(pages * 128):
				val = random.randint(0, 65535)
				# + min(0, (page - 1 % 128))
				data = val.to_bytes(2, 'big')
				bytes_written += 2
				f.write(data)

			# for page in range(pages):
			# 	for b in range(128):
			# 		# + min(0, (page - 1 % 128))
			# 		data = bytes([page & (0xff - b), b])
			# 		bytes_written += 2
			# 		f.write(data)

		logging.info("Written {0} bytes to {1} [{2} pages]".format(bytes_written, filename, pages))

	except Exception as err:
		logging.error("Got error: {0}".format(err))
		raise err
		return None

def lock_address(ser, address, cart=False):
	logging.debug("Locking eeprom address {0}".format(address))
	serial_write(ser, b"LOCK_ADDRESS\n" if not cart else b"CART_LOCK_ADDRESS\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes("{0:x}\n".format(address), "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	error = serial_wait_on(ser, "ADDR_LOCKED", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

def lock_address_and_data(ser, address, word):
	logging.debug("Locking eeprom address {0}".format(address))
	serial_write(ser, b"LOCK_ADDRESS_AND_DATA\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes("{0:x}\n".format(address), "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	serial_wait_on(ser, "AWAIT_DATA_HEX")
	serial_write(ser, bytes("{0:04x}\n".format(word), "utf-8"))
	
	error = serial_wait_on(ser, "ACK_DATA", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	error = serial_wait_on(ser, "ADDR_AND_DATA_LOCKED", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

def write_protect(ser, enable):
	if enable:
		serial_write(ser, b"ENABLE_WRITE_PROTECT\n")
		serial_wait_on(ser, "WRITE_PROTECT_ENABLED")
	else:
		serial_write(ser, b"DISABLE_WRITE_PROTECT\n")
		serial_wait_on(ser, "WRITE_PROTECT_DISABLED")


def sd_files_list(ser):
	serial_write(ser, b"LIST_SD_FILES\n")
	serial_wait_on(ser, "ACK")
	pass

def sd_rom_flash(ser, rom_index):
	serial_write(ser, b"FLASH_SD_ROM\n")
	serial_wait_on(ser, "AWAIT_ADDR_HEX")
	serial_write(ser, bytes("{0:x}\n".format(rom_index), "utf-8"))
	error = serial_wait_on(ser, "ACK_ADDR", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

	serial_wait_on(ser, "ACK")
	pass

# Sega Genesis


def genesis_reset(ser):
	serial_write(ser, b"GENESIS_RESET\n")
	error = serial_wait_on(ser, "ACK_GENESIS", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return

def genesis_reset_set(ser, reset):
	if reset == True:
		serial_write(ser, b"GENESIS_RESET_HOLD\n")
	else:
		serial_write(ser, b"GENESIS_RESET_RELEASE\n")
	error = serial_wait_on(ser, "ACK_GENESIS", "ERR")
	if error:
		logging.error("Error: {0}".format(error))
		return


# Main

def hex_format(input_str):
	s = ""
	for i in range(0, len(input_str), 4):
		if i % 64 == 0:
			s += "\n"
		s += input_str[i:i+4] + " "
	return s

def select_port(input_port):
	return list_ports()[-1]

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='gencart util - A simple terminal program to interact with gencart eeprom/genesys via serial port on arduino.')

    parser.add_argument(
        'action',
        help='action to perform, available actions: debug_info, read_page [address]')

    parser.add_argument(
        'action_arg',
        nargs='?',
        help='action arg')

    parser.add_argument(
        'action_arg2',
        nargs='?',
        help='action arg2',
        default=0)

    parser.add_argument(
        '--baud',
        nargs='?',
        help='set baud rate, default: %(default)s',
        # default=57600
        default=DEFAULT_BAUD
        )

    parser.add_argument(
        '--listports',
        help='lists available serial ports',
        action="store_true")

    parser.add_argument(
        '--port',
        help='serial port name ("-" to show port list)')

    args = parser.parse_args()

    if args.listports == True:
    	for port in list_ports():
    		sys.stdout.write("{:20}\n".format(port))
    	return
    elif args.action == "generate_test_rom":
    	generate_test_rom(args.action_arg, int(args.action_arg2))
    	return

    if args.action == "dumb_crc":
    	dumb_crc()
    	return

    if args.action == "diff_test":
    	diff.test()
    	return

    port = select_port(args.port)

    ser = get_serial(port, args.baud)
    if args.action == "debug_info":
    	debug_info(ser)
    elif args.action == "read_page":
    	logging.info("{0}".format(hex_format(read_page(ser, args.action_arg).hex())))
    elif args.action == "read_page_crc":
    	logging.info("{0}".format(read_page_crc(ser, args.action_arg)))
    elif args.action == "read_pages":
    	logging.info("{0}".format(hex_format(read_pages(ser, int(args.action_arg), int(args.action_arg2)).hex())))
    elif args.action == "write_test_page":
    	write_test_page(ser, args.action_arg)
    elif args.action == "write_fill_page":
    	write_fill_page(ser, int(args.action_arg), args.action_arg2)
    elif args.action == "write_file":
    	write_file(ser, args.action_arg)
    elif args.action == "rom_read_test":
    	rom_read_test(ser, int(args.action_arg))
    elif args.action == "rom_read_test_slow":
    	rom_read_test_slow(ser, int(args.action_arg))
    elif args.action == "verify_file":
    	verify_rom(ser, args.action_arg)
    elif args.action == "dump_rom":
    	dump_rom(ser, args.action_arg, args.action_arg2)
    elif args.action == "lock_address":
    	lock_address(ser, int(args.action_arg))
    elif args.action == "lock_address_and_data":
    	lock_address_and_data(ser, int(args.action_arg), int(args.action_arg2))
    elif args.action == "disable_write_protect":
    	write_protect(ser, False)
    elif args.action == "enable_write_protect":
    	write_protect(ser, True)
    elif args.action == "genesis_reset":
    	genesis_reset(ser)
    elif args.action == "genesis_reset_hold":
    	genesis_reset_set(ser, True)
    elif args.action == "genesis_reset_release":
    	genesis_reset_set(ser, False);

    # cart actions
    elif args.action == "read_page_cart":
    	logging.info("{0}".format(hex_format(read_page(ser, args.action_arg, True).hex())))
    elif args.action == "read_pages_cart":
    	logging.info("{0}".format(hex_format(read_pages(ser, int(args.action_arg), int(args.action_arg2), True).hex())))
    elif args.action == "lock_address_cart":
    	lock_address(ser, int(args.action_arg), True)

    elif args.action == "verify_file_cart":
        verify_rom(ser, args.action_arg, True)

    # sd card actions
    elif args.action == "sd_files_list":
        logging.info(sd_files_list(ser));
    elif args.action == "sd_file_flash":
        logging.info(sd_rom_flash(ser, int(args.action_arg)));

    else:
    	logging.error("Invalid action: {0}".format(args.action))
    # flash_rom(args.port, args.baud, args.romfile)
    pass

if __name__ == '__main__':
    main()