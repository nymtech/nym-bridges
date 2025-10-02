#!/bin/bash

# Configure interface from static file
wg-quick up wg0
wg-quick up wg-q0


# Ping peer
echo "test direct wg ping"
ping -c 10 10.0.0.2

# Keep the container alive without doing anything
tail -f /dev/null
