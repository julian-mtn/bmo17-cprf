import matplotlib.pyplot as plt

# Lire le fichier
n_values = []
results = []
guesss = []
times = []

with open("attack_results.txt") as f:
    for line in f:
        if line.startswith("#") or line.strip() == "":
            continue
        n, tmp, guess, t = map(float, line.strip().split())
        n_values.append(int(n))
        results.append(int(tmp))
        guesss.append(int(guess))
        times.append(t)

# Stats
total_time = sum(times)
total_n = len(n_values)
total_detected = sum(results)
total_guess_right = sum(guesss)
success_percent = total_detected / total_n * 100
guess_right_percent = total_guess_right / total_n * 100

"""
# Créer le graphique
fig, ax = plt.subplots(figsize=(12, 6))
plt.subplots_adjust(bottom=0.25)  # espace pour le texte en bas

# Barplot 0/1
ax.bar(n_values, results, color='red', alpha=0.6)
ax.set_xlabel("n")
ax.set_ylabel("PRF détectée (1=oui, 0=non)")
ax.set_title("Résultats de l'attaque CPRF")
ax.set_ylim(0, 1.2)
ax.set_yticks([0, 1])

# Texte des stats en dessous
stats_text = (
    f"Nombre de tests : {total_n}    |    "
    f"Temps total : {total_time:.0f} ms    |    "
    f"Taux de réussite : {success_percent:.1f}%"
)

fig.text(
    0.5, 0.08, stats_text,
    ha='center',
    fontsize=12,
    bbox=dict(boxstyle="round,pad=0.4", facecolor="white", alpha=0.5)
)

plt.show()
"""


import matplotlib.pyplot as plt

# Création de la figure avec 2 graphiques
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
plt.subplots_adjust(hspace=0.4, bottom=0.18)  # espace entre graphes + texte

# ======================
# Graphique 1 : Barplot
# ======================
ax1.bar(n_values, results, alpha=0.6)
ax1.set_xlabel("n")
ax1.set_ylabel("PRF détectée (1=oui, 0=non)")
ax1.set_title("Résultats de l'attaque CPRF")
ax1.set_ylim(0, 1.2)
ax1.set_yticks([0, 1])

# ======================
# Graphique 2 : Exemple (ligne)
# ======================
ax2.plot(n_values, guesss, alpha=0.6)
ax2.set_xlabel("n")
ax2.set_ylabel("Attaque réussie (1=oui, 0=non)")
ax2.set_title("Résultats des attaques réussies")
ax2.set_ylim(0, 1.2)
ax2.set_yticks([0, 1])

# ======================
# Texte statistiques
# ======================
stats_text = (
    f"Nombre de tests : {total_n}    |    "
    f"Temps total : {total_time:.0f} ms    |    "
    f"Taux de CPRF détectées : {success_percent:.1f}%    |    "
    f"Taux d'attaques réussies : {guess_right_percent:.2f}%"
)

fig.text(
    0.5, 0.05,
    stats_text,
    ha='center',
    fontsize=12,
    bbox=dict(boxstyle="round,pad=0.4", facecolor="white", alpha=0.5)
)

plt.show()

