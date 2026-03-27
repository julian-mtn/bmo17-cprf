#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage:"
    echo "  $0 -n|-h|-l <taille>"
    echo "  $0 -f <max_tries> <taille_N> <taille_M>"
    exit 1
fi

MODE="$1"

case "$MODE" in
    -n|-h|-l)
        TAILLE="$2"

        if ! [[ "$TAILLE" =~ ^[0-9]+$ ]]; then
            echo "Erreur : la taille doit être un entier."
            exit 1
        fi

        gnome-terminal -- bash -c "./server_bmo17 $MODE; exec bash"
        sleep 2
        gnome-terminal -- bash -c "./attack_bmo17 $MODE $TAILLE && python3 display.py; exec bash"
        ;;
    
    -f)
        MAX_TRIES="$2"
        N_SIZE="$3"
        M_SIZE="$4"

        if [ $# -ne 4 ]; then
            echo "Usage: $0 -f <max_tries> <taille_N> <taille_M>"
            exit 1
        fi

        if ! [[ "$MAX_TRIES" =~ ^[0-9]+$ && "$N_SIZE" =~ ^[0-9]+$ && "$M_SIZE" =~ ^[0-9]+$ ]]; then
            echo "Erreur : tous les paramètres doivent être des entiers."
            exit 1
        fi

        gnome-terminal -- bash -c "./server_fweak $N_SIZE $M_SIZE; exec bash"
        sleep 2
        gnome-terminal -- bash -c "./attack_fweak $MAX_TRIES $N_SIZE $M_SIZE && python3 display.py; exec bash"
        ;;
    
    *)
        echo "Erreur : mode invalide. Choisir -n, -h, -l ou -f."
        exit 1
        ;;
esac