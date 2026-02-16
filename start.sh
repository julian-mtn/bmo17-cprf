#!/bin/bash

# Vérifie qu'un paramètre est fourni
if [ $# -lt 1 ]; then
    echo "Usage: $0 <paramètre>"
    exit 1
fi

PARAM="$1"

echo "Lancement de ./server $PARAM"
./server "$PARAM"

echo "Lancement de ./attack $PARAM"
./attack "$PARAM"
