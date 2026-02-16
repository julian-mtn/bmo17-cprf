#!/bin/bash

# Vérifie qu'on a exactement 2 paramètres
if [ $# -ne 2 ]; then
    echo "Usage: $0 -n|-h|-l <taille>"
    echo "  -n  normal"
    echo "  -h  hashed"
    echo "  -l  lazy sampling"
    exit 1
fi

MODE="$1"
TAILLE="$2"

# Vérifie que la taille est un entier
if ! [[ "$TAILLE" =~ ^[0-9]+$ ]]; then
    echo "Erreur : la taille doit être un entier."
    exit 1
fi

# Vérifie le mode (sans le traduire)
case "$MODE" in
    -n|-h|-l)
        ;;
    *)
        echo "Erreur : mode invalide. Choisir -n, -h ou -l."
        exit 1
        ;;
esac

# Lancer le serveur dans un nouveau terminal
gnome-terminal -- bash -c "./server $MODE; exec bash"
sleep 1

# Lancer l'attaque dans un autre terminal
gnome-terminal -- bash -c "./attack $MODE $TAILLE; exec bash"
