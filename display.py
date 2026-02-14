import matplotlib.pyplot as plt

# Lire le fichier
n_values = []
results = []
times = []

with open("attack_results.txt") as f:
    for line in f:
        if line.startswith("#") or line.strip() == "":
            continue
        n, tmp, t = map(float, line.strip().split())
        n_values.append(int(n))
        results.append(int(tmp))
        times.append(t)

# Stats
total_time = sum(times)
total_n = len(n_values)
total_detected = sum(results)
success_percent = total_detected / total_n * 100

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
