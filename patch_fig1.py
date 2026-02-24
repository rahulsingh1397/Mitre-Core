import re

with open("experiments/generate_figures.py", "r", encoding="utf-8") as f:
    code = f.read()

new_func = r"""def fig1_attack_graph(df):
    print("  Fig 1: Attack Correlation Graph (Redesigned)")
    
    # Select a single, representative campaign that has a good mix of tactics
    # We will look for a cluster with 6-8 events and diverse tactics
    best_cluster = None
    max_tactics = 0
    for c, grp in df.groupby("pred_cluster"):
        tactics = {ATTACK_TYPE_TO_TACTIC.get(a, "UNKNOWN") for a in grp["MalwareIntelAttackType"]} - {"UNKNOWN"}
        if 5 <= len(grp) <= 8 and len(tactics) > max_tactics:
            max_tactics = len(tactics)
            best_cluster = c
            
    if best_cluster is None:
        best_cluster = df["pred_cluster"].iloc[0]
        
    campaign_df = df[df["pred_cluster"] == best_cluster].copy()
    # Sort by EndDate to ensure chronological order
    campaign_df = campaign_df.sort_values("EndDate").reset_index(drop=True)
    
    G = nx.DiGraph()
    for i, row in campaign_df.iterrows():
        tactic = ATTACK_TYPE_TO_TACTIC.get(row.get("MalwareIntelAttackType"), "Unknown")
        color = TACTIC_COLORS.get(tactic, "#94a3b8")
        G.add_node(i, tactic=tactic, color=color, label=tactic.replace(" ", "\n"))
        
    for i in range(len(campaign_df) - 1):
        G.add_edge(i, i+1, etype="seq")
        
    # Add a couple of shared IP backward edges to illustrate correlation, if applicable
    ip_edges = []
    for i in range(len(campaign_df)):
        for j in range(i + 2, len(campaign_df)):
            if (campaign_df.loc[i, "SourceAddress"] == campaign_df.loc[j, "SourceAddress"] or 
                campaign_df.loc[i, "DestinationAddress"] == campaign_df.loc[j, "DestinationAddress"] or
                campaign_df.loc[i, "DeviceAddress"] == campaign_df.loc[j, "DeviceAddress"]):
                G.add_edge(i, j, etype="ip")
                ip_edges.append((i, j))
                break # Just add one per node to keep it clean

    fig, ax = plt.subplots(figsize=(14, 4))
    fig.patch.set_facecolor("#ffffff")
    ax.set_facecolor("#ffffff")
    
    # Layout: straight line
    pos = {i: (i * 2, 0) for i in range(len(campaign_df))}
    
    seq_e = [(u,v) for u,v,d in G.edges(data=True) if d["etype"]=="seq"]
    ip_e  = [(u,v) for u,v,d in G.edges(data=True) if d["etype"]=="ip"]
    
    # Draw sequential edges (arrows)
    nx.draw_networkx_edges(G, pos, edgelist=seq_e, ax=ax, edge_color="#3b82f6", 
                           alpha=0.8, width=2.5, arrows=True, arrowsize=20, connectionstyle="arc3,rad=0")
                           
    # Draw shared IP edges (dashed curves)
    nx.draw_networkx_edges(G, pos, edgelist=ip_e, ax=ax, edge_color="#f59e0b", 
                           alpha=0.7, width=1.5, style="dashed", connectionstyle="arc3,rad=-0.4")
                           
    # Draw nodes
    node_colors = [G.nodes[n]["color"] for n in G.nodes()]
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=1200, edgecolors="#000000", linewidths=1.5)
    
    # Draw labels (tactics)
    for i in G.nodes():
        tactic_label = G.nodes[i]["label"]
        ax.text(pos[i][0], pos[i][1] - 0.25, tactic_label, ha="center", va="top", fontsize=10, fontweight="bold", color="#000000")
        
    # Draw step numbers inside nodes
    labels = {i: str(i+1) for i in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels, font_size=12, font_color="#ffffff", font_weight="bold")
    
    # Add legend
    handles = [Line2D([0],[0], color="#3b82f6", lw=2.5, label="Temporal Sequence"),
               Line2D([0],[0], color="#f59e0b", lw=1.5, ls="--", label="Shared IP / Host Indicator")]
    ax.legend(handles=handles, loc="upper right", fontsize=10, framealpha=0.9, edgecolor="#000000")
    
    ax.set_title("MITRE-CORE Alert Correlation: Single Campaign Progression", fontsize=14, fontweight="bold", color="#000000", pad=20)
    
    # Set limits to fit labels
    ax.set_xlim(-1, (len(campaign_df)-1)*2 + 1)
    ax.set_ylim(-1.0, 0.6)
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
