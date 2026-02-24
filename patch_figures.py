import re
with open('experiments/generate_figures.py', 'r') as f:
    code = f.read()

code = re.sub(r'plt\.rcParams\.update\(\{.*?\}\)', '''plt.rcParams.update({
    "figure.facecolor":"#ffffff","axes.facecolor":"#ffffff",
    "axes.edgecolor":"#000000","axes.labelcolor":"#000000",
    "axes.titlecolor":"#000000","xtick.color":"#000000",
    "ytick.color":"#000000","text.color":"#000000",
    "grid.color":"#e5e7eb","grid.alpha":0.7,
    "legend.facecolor":"#ffffff","legend.edgecolor":"#000000",
    "legend.labelcolor":"#000000","font.size":11,
    "axes.titlesize":13,"axes.labelsize":11,
})''', code, flags=re.DOTALL)

code = code.replace('fig.patch.set_facecolor("#0f172a")', 'fig.patch.set_facecolor("#ffffff")')
code = code.replace('ax.set_facecolor("#1e293b")', 'ax.set_facecolor("#ffffff")')
code = code.replace('ax.set_facecolor("#0f172a")', 'ax.set_facecolor("#ffffff")')
code = code.replace('ax1.set_facecolor("#1e293b")', 'ax1.set_facecolor("#ffffff")')
code = code.replace('ax2.set_facecolor("#1e293b")', 'ax2.set_facecolor("#ffffff")')
code = code.replace('ax2.set_facecolor("#0f172a")', 'ax2.set_facecolor("#ffffff")')
code = code.replace('facecolor="#0f172a"', 'facecolor="#ffffff"')
code = code.replace('color="#f1f5f9"', 'color="#000000"')
code = code.replace('edgecolor="#0f172a"', 'edgecolor="#000000"')
code = code.replace('color="#94a3b8"', 'color="#475569"')
code = code.replace('dpi=150', 'dpi=300')

with open('experiments/generate_figures.py', 'w') as f:
    f.write(code)
