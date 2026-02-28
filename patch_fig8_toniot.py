import matplotlib.pyplot as plt
import numpy as np

def generate_fig8():
    plt.style.use('ggplot')
    
    # Data from Table XI
    datasets = ['UNSW-NB15\n(Enterprise IT)', 'TON_IoT\n(Industrial IoT)']
    
    # Use max(0, val) for display purposes if negative, or just let them go negative
    # But for visual comparison, usually setting a floor at 0 for completely failed methods is clearer
    # We'll use the exact values, but if negative, they'll just point down
    
    uf_ari = [0.2977, -0.0020]
    uf_nmi = [0.4882, 0.0053]
    
    hgnn_ari = [0.7779, 0.0688] # Zero-shot performance on TON_IoT
    hgnn_nmi = [0.7664, 0.2435]
    
    hgnn_ft_ari = [0.7779, 0.0738] # FT performance (same for UNSW as it's the source)
    hgnn_ft_nmi = [0.7664, 0.2605]

    x = np.arange(len(datasets))
    width = 0.25

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Plot ARI
    rects1_ari = ax1.bar(x - width, uf_ari, width, label='Union-Find', color='#e24a33')
    rects2_ari = ax1.bar(x, hgnn_ari, width, label='HGNN (Zero-Shot)', color='#348abd')
    rects3_ari = ax1.bar(x + width, hgnn_ft_ari, width, label='HGNN (Fine-Tuned)', color='#988ed5')

    ax1.set_ylabel('ARI Score')
    ax1.set_title('Cross-Domain Generalization (ARI)')
    ax1.set_xticks(x)
    ax1.set_xticklabels(datasets)
    ax1.set_ylim(-0.05, 0.9)
    ax1.legend()

    # Plot NMI
    rects1_nmi = ax2.bar(x - width, uf_nmi, width, label='Union-Find', color='#e24a33')
    rects2_nmi = ax2.bar(x, hgnn_nmi, width, label='HGNN (Zero-Shot)', color='#348abd')
    rects3_nmi = ax2.bar(x + width, hgnn_ft_nmi, width, label='HGNN (Fine-Tuned)', color='#988ed5')

    ax2.set_ylabel('NMI Score')
    ax2.set_title('Cross-Domain Generalization (NMI)')
    ax2.set_xticks(x)
    ax2.set_xticklabels(datasets)
    ax2.set_ylim(-0.05, 0.9)
    ax2.legend()

    fig.tight_layout()
    plt.savefig('docs/figures/fig8_modern_dataset.png', dpi=300, bbox_inches='tight')
    print("Saved docs/figures/fig8_modern_dataset.png")

if __name__ == "__main__":
    import matplotlib.pyplot as plt
    generate_fig8()
