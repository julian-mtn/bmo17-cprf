#!/bin/bash

# Vérifie qu'on a au moins 1 paramètre
if [ $# -lt 1 ]; then
    echo "Usage: $0 -n|-h|-l|-f <taille>"
    echo "  -n  normal"
    echo "  -h  hashed"
    echo "  -l  lazy sampling"
    echo "  -f  fweak"
    exit 1
fi

MODE="$1"
TAILLE="$2"  # Peut être vide pour -f

# Vérifie que la taille est un entier si nécessaire
if [[ "$MODE" != "-f" ]]; then
    if ! [[ "$TAILLE" =~ ^[0-9]+$ ]]; then
        echo "Erreur : la taille doit être un entier."
        exit 1
    fi
fi

case "$MODE" in
    -n|-h|-l)
        # Lancer BMO17
        gnome-terminal -- bash -c "./server_bmo17 $MODE; exec bash"
        sleep 2
        gnome-terminal -- bash -c "./attack_bmo17 $MODE $TAILLE && python3 display.py; exec bash"
        ;;
    -f)
        # Lancer FWEAK
        gnome-terminal -- bash -c "./server_fweak; exec bash"
        sleep 2
        gnome-terminal -- bash -c "./attack_fweak && python3 display.py; exec bash"
        ;;
    *)
        echo "Erreur : mode invalide. Choisir -n, -h, -l ou -f."
        exit 1
        ;;
esac