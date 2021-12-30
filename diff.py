import logging


def diff_byte(b1, b2):
	return 

def diff_bytearrays(byte_array1, byte_array2):
	byte_count = len(byte_array1)

	comparison_groups = []
	curent_group = {"start": 0, "end": 0, "match": True}
	for idx in range(byte_count):
		b1 = byte_array1[idx]
		b2 = byte_array2[idx]
		if (b1 == b2):
			if not curent_group["match"]:
				comparison_groups.append(curent_group)
				curent_group = {"start": idx, "end": idx, "match": True}
			else:
				curent_group["end"] = idx
		else:
			if curent_group["match"]:
				comparison_groups.append(curent_group)
				curent_group = {"start": idx, "end": idx, "match": False}
			else:
				curent_group["end"] = idx
	comparison_groups.append(curent_group)
	return comparison_groups

# stolen from stack overflow (blender?)
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def debug_format(input_bytes, expected_bytes, diff, inline_correction=True, failues_only=True, address_offset=0):

	# failed_ranges = [range(r["start"], r["end"] + 1) for r in diff if diff["match"] == False]
	failed_ranges = [range(r["start"], r["end"] + 1) for r in diff if r["match"] == False]
	failed_indexes = [idx for subrange in failed_ranges for idx in subrange]

	fail_color = bcolors.FAIL
	expected_color = bcolors.WARNING

	input_str = input_bytes.hex()
	expected_str = expected_bytes.hex()
	s = ""
	line = "@0x{0:04x}: ".format(address_offset)
	line_has_failure = False
	for i in range(0, len(input_str), 4):
		if i % 32 == 0:
			if failues_only and line_has_failure:
				s += line + "\n"
			line_has_failure = False
			line = "@0x{0:04x}: ".format(int(i / 2 + address_offset))

		tmp_str = ""
		first_byte_failed = i / 2 in failed_indexes
		second_byte_failed = i / 2 + 1 in failed_indexes
		tmp_str += (fail_color if first_byte_failed else "") + input_str[i:i+2] \
			+ (expected_color + "[" + expected_str[i:i+2] + "]" if inline_correction and first_byte_failed else "") \
			+ bcolors.ENDC
		tmp_str += (fail_color if second_byte_failed else "") + input_str[i+2:i+4] \
			+ (expected_color + "[" + expected_str[i+2:i+4] + "]" if inline_correction and second_byte_failed else "") \
			+ bcolors.ENDC + " "
		
		#adjust lenghts so the bytes align across rows
		if inline_correction:
			colors_len = (len(fail_color) + len(expected_color) if first_byte_failed else 0) \
				+ (len(fail_color) + len(expected_color) if second_byte_failed else 0) \
				+ (2 * len(bcolors.ENDC))
			str_len = len(tmp_str) - colors_len
			# print("str: {2}, colors len: {0}, str len: {1}".format(colors_len, str_len, tmp_str))
			tmp_str += (" " * (14 - str_len))
		line += tmp_str

		if not line_has_failure:
			line_has_failure = first_byte_failed or second_byte_failed

	if failues_only and line_has_failure:
		s += line

	s += "\nFailed byte count: {0}/{1} [{2}%]".format(len(failed_indexes), len(input_bytes), int(100 * len(failed_indexes)/len(input_bytes) ))

	return s

def show_diff(bytes1, bytes2, address_offset=0):
	diff = diff_bytearrays(bytes1, bytes2)
	logging.info("Generating full page diff, this can take up to 30 seconds...")
	output_str = debug_format(bytes1, bytes2, diff, address_offset=address_offset)
	logging.info("\n" + output_str)

def test():
	b1 = b'\x00\x01\x04\x03\x04\x02\x02\x07' * 4
	b2 = b'\x00\x01\x02\x03\x04\x05\x06\x07' * 4
	logging.info("Doing a diff test {0} vs {1}".format(b1, b2))
	diff = diff_bytearrays(b1, b2)
	logging.info("Diff output {0}".format(diff_bytearrays(b1, b2)))

	show_diff(b1, b2)