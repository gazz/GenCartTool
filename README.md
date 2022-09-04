## cli interface to homebuilt GenMemBlock that will remotely flash eeproms(or eventualy sram) & control Sega Genesys execution on the fly

python main.py read_pages 0 3
python main.py read_page 0
python main.py read_page 1
python main.py disable_write_protect
python main.py write_fill_page 0 ab
python main.py write_fill_page 0 ac
python main.py read_pages 0 
python main.py lock_address_and_data 0 0
python main.py lock_address 0
python main.py lock_address_and_data 0 44461
python main.py write_fill_page 0 ad
python main.py write_file mspacman.bin 
python main.py verify_file mspacman.bin 
python main.py read_pages 0 5
python main.py write_file test
python main.py verify_file test.bin 
python main.py generate_test_rom test.bin 64

# genesis interaction
python main.py /dev/cu.wchusbserial141220 genesis_reset

# show bin in a readable hex fmt
