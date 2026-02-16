#!/bin/bash

# Vérifie qu'un paramètre est fourni
if [ $# -lt 1 ]; then
    echo "Usage: $0 <paramètre>"
    exit 1
fi

PARAM="$1"

# Lancer le serveur dans un nouveau terminal
echo "Lancement de ./server $PARAM dans un terminal"
gnome-terminal -- bash -c "./server $PARAM; exec bash"

sleep 1

# Lancer l'attaque dans un autre terminal
echo "Lancement de ./attack $PARAM dans un autre terminal"
gnome-terminal -- bash -c "./attack $PARAM; exec bash"
