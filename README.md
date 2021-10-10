## cli interface to homebuilt GenMemBlock that will remotely flash eeproms(or eventualy sram) & control Sega Genesys execution on the fly

python main.py /dev/cu.wchusbserial141220 read_pages 0 3
python main.py /dev/cu.wchusbserial141220 read_page 0
python main.py /dev/cu.wchusbserial141220 read_page 1
python main.py /dev/cu.wchusbserial141220 disable_write_protect
python main.py /dev/cu.wchusbserial141220 write_fill_page 0 ab
python main.py /dev/cu.wchusbserial141220 write_fill_page 0 ac
python main.py /dev/cu.wchusbserial141220 read_pages 0 
python main.py /dev/cu.wchusbserial141220 lock_address_and_data 0 0
python main.py /dev/cu.wchusbserial141220 lock_address 0
python main.py /dev/cu.wchusbserial141220 lock_address_and_data 0 44461
python main.py /dev/cu.wchusbserial141220 write_fill_page 0 ad
python main.py /dev/cu.wchusbserial141220 write_file mspacman.bin 
python main.py /dev/cu.wchusbserial141220 verify_rom mspacman.bin 
python main.py /dev/cu.wchusbserial141220 read_pages 0 5
python main.py /dev/cu.wchusbserial141220 write_file test
python main.py /dev/cu.wchusbserial141220 verify_rom test.bin 
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 0
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 1
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 10
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 12
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 14
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 15
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 2
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 8
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 16
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 64
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 256
python main.py /dev/cu.wchusbserial141220 write_file mspacman.bin
python main.py /dev/cu.wchusbserial141220 reset_genesis_hold
python main.py /dev/cu.wchusbserial141220 reset_genesis
python main.py /dev/cu.wchusbserial141220 genesis_reset_release
python main.py /dev/cu.wchusbserial141220 genesis_reset_hold
python main.py /dev/cu.wchusbserial141220 write_file test.bin 
python main.py /dev/cu.wchusbserial141220 genesis_reset
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 4
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 128
python main.py /dev/cu.wchusbserial141220 write_file tests/Omega\ Race\ \(J\)\ \[x\].bin 
python main.py /dev/cu.wchusbserial141220 verify_file mspacman.bin
python main.py /dev/cu.wchusbserial141220 verify_file tests/Omega\ Race\ \(J\)\ \[x\].bin \
python main.py /dev/cu.wchusbserial141220 verify_file tests/Omega\ Race\ \(J\)\ \[x\].bin 
python main.py /dev/cu.wchusbserial143220 generate_test_rom test.bin 1024
python main.py /dev/cu.wchusbserial141220 write_file test.bin