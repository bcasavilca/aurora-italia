#!/bin/bash
# backup diario VETRINA-AURORA-HTML: data + fotos
DEST="$HOME/backups/vetrina"
mkdir -p "$DEST"
tar -czf "$DEST/vetrina-$(date +%Y%m%d).tar.gz" -C "$HOME/site-anuncios" data fotos 2>/dev/null
ls -t "$DEST"/vetrina-*.tar.gz | tail -n +8 | xargs -r rm --
