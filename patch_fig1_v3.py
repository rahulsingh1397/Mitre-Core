import re

with open("experiments/generate_figures.py", "r", encoding="utf-8") as f:
    code = f.read()

new_func = r"""def fig1_attack_graph(df):
    print("  Fig 1: Attack Correlation Graph (Redesigned with IPs)")
    
    # Select a single, representative campaign with 4-6 events to avoid overcrowding the horizontal layout
    best_cluster = None
    max_tactics = 0
    for c, grp in df.groupby("pred_cluster"):
        tactics = {ATTACK_TYPE_TO_TACTIC.get(a, "UNKNOWN") for a in grp["MalwareIntelAttackType"]} - {"UNKNOWN"}
        if 4 <= len(grp) <= 6 and len(tactics) > max_tactics:
            max_tactics = len(tactics)
            best_cluster = c
            
    if best_cluster is None:
        best_cluster = df["pred_cluster"].iloc[0]
        
    campaign_df = df[df["pred_cluster"] == best_cluster].copy()
    # Sort by EndDate to ensure chronological order
    campaign_df = campaign_df.sort_values("EndDate").reset_index(drop=True)
    
    # Keep only the first 5 events if it's too long
    if len(campaign_df) > 5:
        campaign_df = campaign_df.head(5)
    
    G = nx.DiGraph()
    for i, row in campaign_df.iterrows():
        tactic = ATTACK_TYPE_TO_TACTIC.get(row.get("MalwareIntelAttackType"), "Unknown")
        color = TACTIC_COLORS.get(tactic, "#94a3b8")
        src_ip = row.get("SourceAddress", "Unknown")
        dst_ip = row.get("DestinationAddress", "Unknown")
        
        G.add_node(i, tactic=tactic, color=color, src=src_ip, dst=dst_ip)
        
    for i in range(len(campaign_df) - 1):
        G.add_edge(i, i+1, etype="seq")
        
    fig, ax = plt.subplots(figsize=(16, 5))
    fig.patch.set_facecolor("#ffffff")
    ax.set_facecolor("#ffffff")
    
    # Layout: straight line, spread out
    pos = {i: (i * 3.5, 0) for i in range(len(campaign_df))}
    
    seq_e = [(u,v) for u,v,d in G.edges(data=True) if d["etype"]=="seq"]
    
    # Draw sequential edges (arrows)
    nx.draw_networkx_edges(G, pos, edgelist=seq_e, ax=ax, edge_color="#3b82f6", 
                           alpha=0.8, width=3.5, arrows=True, arrowsize=25, connectionstyle="arc3,rad=0")
                           
    # Draw nodes
    node_colors = [G.nodes[n]["color"] for n in G.nodes()]
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=1800, edgecolors="#000000", linewidths=2)
    
    # Draw labels (tactics & IPs)
    for i in G.nodes():
        src = G.nodes[i]["src"]
        dst = G.nodes[i]["dst"]
        tactic = G.nodes[i]["tactic"].replace(" ", "\n")
        
        # Top label (IPs)
        ip_label = f"Attacker IP:\n{src}\n\nTarget IP:\n{dst}"
        ax.text(pos[i][0], pos[i][1] + 0.25, ip_label, ha="center", va="bottom", fontsize=10, 
                fontweight="normal", color="#000000", 
                bbox=dict(facecolor='#f8fafc', edgecolor='#94a3b8', boxstyle='round,pad=0.6', alpha=0.95))
                
        # Bottom label (Tactic)
        ax.text(pos[i][0], pos[i][1] - 0.25, tactic, ha="center", va="top", fontsize=11, 
                fontweight="bold", color="#000000")
        
    # Draw step numbers inside nodes
    labels = {i: str(i+1) for i in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels, font_size=16, font_color="#ffffff", font_weight="bold")
    
    # Add legend
    handles = [Line2D([0],[0], color="#3b82f6", lw=3.5, label="Attack Progression")]
    ax.legend(handles=handles, loc="upper right", fontsize=12, framealpha=1.0, edgecolor="#000000")
    
    ax.set_title("MITRE-CORE Alert Correlation: Attack Chain Progression", fontsize=16, fontweight="bold", color="#000000", pad=30)
    
    ax.set_xlim(-1.5, (len(campaign_df)-1)*3.5 + 1.5)
    ax.set_ylim(-1.2, 1.8)
    ax.axis("off")
    
    out = FIGURES_DIR / "fig1_attack_graph.png"
    plt.tight_layout()
    plt.savefig(out, dpi=300, bbox_inches="tight", facecolor="#ffffff")
    plt.close()
    print(f"    -> {out}")
    return out
"""

pattern = re.compile(r"def fig1_attack_graph\(df\):.*?return out", re.DOTALL)
code = pattern.sub(new_func, code)

with open("experiments/generate_figures.py", "w", encoding="utf-8") as f:
    f.write(code)
