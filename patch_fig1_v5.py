import re

with open("experiments/generate_figures.py", "r", encoding="utf-8") as f:
    code = f.read()

new_func = r"""def fig1_attack_graph(df):
    print("  Fig 1: Attack Correlation Graph (Multiple Chains with Timestamps)")
    
    # We will select 3 distinct campaigns to display as parallel horizontal chains
    campaigns_to_show = []
    
    # Try to find 3 good campaigns (size 3-5, good mix of tactics)
    for c, grp in df.groupby("pred_cluster"):
        tactics = {ATTACK_TYPE_TO_TACTIC.get(a, "UNKNOWN") for a in grp["MalwareIntelAttackType"]} - {"UNKNOWN"}
        if 3 <= len(grp) <= 5 and len(tactics) >= 2:
            campaigns_to_show.append(c)
            if len(campaigns_to_show) == 3:
                break
                
    # Fallback if we didn't find 3 ideal ones
    if len(campaigns_to_show) < 3:
        all_clusters = list(df["pred_cluster"].unique())
        for c in all_clusters:
            if c not in campaigns_to_show:
                campaigns_to_show.append(c)
            if len(campaigns_to_show) == 3:
                break
                
    fig, ax = plt.subplots(figsize=(16, 9))
    fig.patch.set_facecolor("#ffffff")
    ax.set_facecolor("#ffffff")
    
    G = nx.DiGraph()
    pos = {}
    
    # Y-coordinates for the 3 parallel chains (top to bottom)
    y_coords = [2.5, 0, -2.5]
    
    node_counter = 0
    max_x = 0
    
    # Format for timestamp
    import pandas as pd
    
    for c_idx, cluster_id in enumerate(campaigns_to_show):
        campaign_df = df[df["pred_cluster"] == cluster_id].copy()
        
        # Parse EndDate and sort
        if "EndDate" in campaign_df.columns:
            campaign_df["parsed_time"] = pd.to_datetime(campaign_df["EndDate"], errors='coerce')
            campaign_df = campaign_df.sort_values("parsed_time").reset_index(drop=True)
            
        y_pos = y_coords[c_idx]
        chain_nodes = []
        
        for i, row in campaign_df.iterrows():
            tactic = ATTACK_TYPE_TO_TACTIC.get(row.get("MalwareIntelAttackType"), "Unknown")
            color = TACTIC_COLORS.get(tactic, "#94a3b8")
            src_ip = row.get("SourceAddress", "Unknown")
            dst_ip = row.get("DestinationAddress", "Unknown")
            
            # Format timestamp for display
            try:
                dt = pd.to_datetime(row.get("EndDate", ""))
                ts_str = dt.strftime("%H:%M:%S")
            except:
                ts_str = f"T+{i*5}m" # Fallback if parsing fails
                
            G.add_node(node_counter, 
                      tactic=tactic, 
                      color=color, 
                      src=src_ip, 
                      dst=dst_ip,
                      ts=ts_str,
                      chain_id=c_idx)
            
            x_pos = i * 3.5
            pos[node_counter] = (x_pos, y_pos)
            chain_nodes.append(node_counter)
            max_x = max(max_x, x_pos)
            
            node_counter += 1
            
        # Add sequential edges for this chain
        for i in range(len(chain_nodes) - 1):
            G.add_edge(chain_nodes[i], chain_nodes[i+1], etype="seq")
            
        # Draw a subtle background bounding box/line for the campaign
        if len(chain_nodes) > 0:
            ax.add_patch(plt.Rectangle((-1.0, y_pos - 1.0), 
                                     (len(chain_nodes)-1)*3.5 + 2.0, 2.0, 
                                     fill=True, color="#f8fafc", alpha=0.6, 
                                     edgecolor="#cbd5e1", lw=1, ls="--", zorder=0))
            ax.text(-1.2, y_pos, f"Campaign {cluster_id}", 
                    ha="right", va="center", fontsize=12, fontweight="bold", color="#334155", rotation=90)
    
    seq_e = [(u,v) for u,v,d in G.edges(data=True) if d["etype"]=="seq"]
    
    # Draw sequential edges (arrows)
    nx.draw_networkx_edges(G, pos, edgelist=seq_e, ax=ax, edge_color="#3b82f6", 
                           alpha=0.8, width=3.0, arrows=True, arrowsize=20, connectionstyle="arc3,rad=0")
                           
    # Draw nodes
    node_colors = [G.nodes[n]["color"] for n in G.nodes()]
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=1500, edgecolors="#000000", linewidths=1.5)
    
    # Draw labels (tactics & IPs)
    for n in G.nodes():
        src = G.nodes[n]["src"]
        dst = G.nodes[n]["dst"]
        tactic = G.nodes[n]["tactic"].replace(" ", "\n")
        ts = G.nodes[n]["ts"]
        
        # Top label (IPs)
        ip_label = f"Src: {src}\nDst: {dst}"
        ax.text(pos[n][0], pos[n][1] + 0.3, ip_label, ha="center", va="bottom", fontsize=9, 
                fontweight="normal", color="#1e293b", 
                bbox=dict(facecolor='#ffffff', edgecolor='#cbd5e1', boxstyle='round,pad=0.4', alpha=0.9))
                
        # Bottom label (Tactic & Timestamp)
        bottom_label = f"{tactic}\n\n[ {ts} ]"
        ax.text(pos[n][0], pos[n][1] - 0.28, bottom_label, ha="center", va="top", fontsize=10, 
                fontweight="bold", color="#0f172a")
        
    # Draw step numbers inside nodes
    labels = {n: str(n - min([k for k,v in G.nodes(data=True) if v['chain_id'] == G.nodes[n]['chain_id']]) + 1) for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels, font_size=14, font_color="#ffffff", font_weight="bold")
    
    # Add legend
    handles = [Line2D([0],[0], color="#3b82f6", lw=3.0, label="Temporal Progression Sequence")]
    ax.legend(handles=handles, loc="upper right", fontsize=11, framealpha=1.0, edgecolor="#000000")
    
    ax.set_title("MITRE-CORE Alert Correlation: Multiple Parallel Attack Chains", fontsize=16, fontweight="bold", color="#000000", pad=20)
    
    ax.set_xlim(-2.0, max_x + 1.5)
    ax.set_ylim(min(y_coords) - 1.5, max(y_coords) + 1.8)
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
