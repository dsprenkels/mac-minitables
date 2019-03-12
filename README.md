# mac-minitables

This project is a small proof-of-concept, showing why hashing MAC-addresses does not provide
anonymity. I.e. the hashing of MAC-addresses is easily reversible.

## Usage

```
# Clone the repository
git clone https://github.com/dsprenkels/mac-minitables.git

# Build the app
cargo build --release

# Generate the lookup-tables for a bunch of popular prefixes
# THIS WILL TAKE A REALLY LONG TIME
./target/release/mac-minitables compute --table-dir tables/ lists/popular_addrs.txt

# Compute the sha256 hash of a MAC address
./target/release/mac-minitables hash A0:39:F7:1E:22:86 | tee address-hash.txt

# Do a lookup in the tables and find a preimage of the hash
./target/release/mac-minitables lookup --table-dir tables/ "$(cat address-hash.txt)"
