#!/bin/bash

# Configure interface from static file
wg-quick up wg1
wg-quick up wg-q1

# Keep container alive
tail -f /dev/null
