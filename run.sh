if [ $? -ne 0 ]; then
    echo "ROM argument missing, usage: run.sh <rom>"
    exit 1
fi
rom=$1
echo "Loading ${rom}"
BASE_PATH=$PY_GENCART_PATH

python $BASE_PATH/main.py write_file "$1"
python $BASE_PATH/main.py genesis_reset