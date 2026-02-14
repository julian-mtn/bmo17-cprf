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

# Créer le graphique
fig, ax = plt.subplots(figsize=(14, 5)) 
plt.subplots_adjust(right=0.75)  # laisse 25% pour le texte à droite


ax.bar(n_values, results, color='red', alpha=0.6)
ax.set_xlabel("n")
ax.set_ylabel("PRF détectée (1=oui, 0=non)")
ax.set_title("Résultats de l'attaque CPRF")
ax.set_ylim(0, 1.2)
ax.set_yticks([0, 1])

textstr = f"Nombre de tests (n) : {total_n}\nTemps total : {total_time:.0f} ms"

ax.text(1.05, 0.5, textstr, transform=ax.transAxes, fontsize=12,
        verticalalignment='center', bbox=dict(boxstyle="round,pad=0.5", facecolor='white', alpha=0.4))

plt.show()
