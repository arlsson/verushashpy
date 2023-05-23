import os
import configparser
import time
from authproxy import AuthServiceProxy, JSONRPCException

import tests.verus_hash
import verushash

verus_conf_dir = os.getcwd()


def get_rpc_connection():
    # Create a ConfigParser instance
    config = configparser.ConfigParser()

    # Read the Verus configuration file
    verus_conf_path = os.path.join(verus_conf_dir, 'vrsctest.conf')
    config.read(verus_conf_path)

    # Retrieve the RPC details
    rpc_user = config['rpc']['rpcuser']
    rpc_password = config['rpc']['rpcpassword']
    rpc_port = config['rpc']['rpcport']
    # Create a connection to the Verus client
    connection = f"http://{rpc_user}:{rpc_password}@127.0.0.1:{rpc_port}"
    try:
        verus_connection = AuthServiceProxy(connection)
        return verus_connection
    except JSONRPCException as e:
        print(f"Could not connect to the Verus client: {e}")
        return None


def hash_header(serialized_header):
    if serialized_header[0] == 4 and serialized_header[2] >= 1 and len(serialized_header) >= 144:
        if serialized_header[143] < 3:
            return verushash.verushash_v2b(serialized_header)
        elif serialized_header[143] < 4:
            return verushash.verushash_v2b1(serialized_header)
        else:
            return verushash.verushash_v2b2(serialized_header)
    else:
        return verushash.verushash(serialized_header)


def process_block(i):
    rpc_connection = get_rpc_connection()

    # Get block hash
    expected_hash = rpc_connection.getblockhash(i)
    block_header = rpc_connection.getblockheader(expected_hash, False)

    try:
        serialized_header = bytes.fromhex(block_header)
    except ValueError:
        raise Exception(f"Error converting block '{block_header}' to bytearray")

    block_hash = hash_header(serialized_header)
    byte_reversed_hash = tests.verus_hash.byte_reverse_hex_string(tests.verus_hash.ps(block_hash))

    if byte_reversed_hash != expected_hash:
        raise Exception(f"Failure at block {i}, expected hash: {expected_hash}, Actual Hash: {byte_reversed_hash}")

    print(f"Successfully hashed block {i}: {byte_reversed_hash}")


# Get RPC connection
rpc_connection = get_rpc_connection()

# Get the block count
block_count = rpc_connection.getblockcount()
print(block_count)

# Start timing
start_time = time.time()

for i in range(1, block_count + 1):
    process_block(i)

# Calculate time taken
time_taken = time.time() - start_time

# Calculate hashes per second
hashes_per_second = block_count / time_taken

print(f"Finished processing all blocks. Hashes per second: {hashes_per_second}")
