#!/bin/bash
# Nightly backup of /var/www to the archive volume
SRC="/var/www"
DEST="/mnt/archive/www-$(date +%F).tar.gz"
tar -czf "$DEST" "$SRC"
echo "Backup written to $DEST"
