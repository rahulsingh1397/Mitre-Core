import re

with open("experiments/generate_figures.py", "r", encoding="utf-8") as f:
    code = f.read()

new_func = r"""def fig1_attack_graph():
    print("  Fig 1: Attack Correlation Graph (Multiple Chains with Timestamps from Real Data)")
    
    import pandas as pd
    import networkx as nx
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    from pathlib import Path
    
    # Load real NSL-KDD formatted data
    try:
        real_df = pd.read_csv(PROJECT_ROOT / "datasets" / "nsl_kdd" / "mitre_format.csv")
        attack_df = real_df[real_df['alert_type'] == 'attack'].copy()
        attack_df['timestamp'] = pd.to_datetime(attack_df['timestamp'])
        
        # We need campaigns that have multiple steps
        campaign_counts = attack_df['campaign_id'].value_counts()
        valid_campaigns = campaign_counts[(campaign_counts >= 3) & (campaign_counts <= 5)].index.tolist()
        
        campaigns_to_show = []
        for c in valid_campaigns:
            grp = attack_df[attack_df['campaign_id'] == c]
            tactics = set(grp['tactic'].dropna().unique())
            if len(tactics) >= 2:
                campaigns_to_show.append(c)
            if len(campaigns_to_show) == 3:
                break
                
        if len(campaigns_to_show) < 3:
            campaigns_to_show = valid_campaigns[:3]
            
    except Exception as e:
        print(f"    Failed to load real data: {e}")
        return None

    fig, ax = plt.subplots(figsize=(16, 9))
    fig.patch.set_facecolor("#ffffff")
    ax.set_facecolor("#ffffff")
    
    G = nx.DiGraph()
    pos = {}
    
    # Y-coordinates for the 3 parallel chains (top to bottom)
    y_coords = [2.5, 0, -2.5]
    
    node_counter = 0
    max_x = 0
    
    for c_idx, cluster_id in enumerate(campaigns_to_show):
        campaign_df = attack_df[attack_df["campaign_id"] == cluster_id].copy()
        campaign_df = campaign_df.sort_values("timestamp").reset_index(drop=True)
            
        y_pos = y_coords[c_idx]
        chain_nodes = []
        
        for i, row in campaign_df.iterrows():
            tactic = str(row.get("tactic", "Unknown")).upper()
            if tactic == "NONE" or tactic == "NAN": tactic = "UNKNOWN"
            
            color = TACTIC_COLORS.get(tactic, "#94a3b8")
            # If color not found, try to find a matching one by substring or use default
            if color == "#94a3b8":
                for k, v in TACTIC_COLORS.items():
                    if tactic in k or k in tactic:
                        color = v
                        break
                        
            src_ip = row.get("src_ip", "Unknown")
            dst_ip = row.get("dst_ip", "Unknown")
            
            ts_str = row["timestamp"].strftime("%H:%M:%S")
                
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
        
        # Use simple string concatenation to avoid regex newline substitution bugs in Python
        tactic_str = G.nodes[n]["tactic"]
        t_parts = tactic_str.split(" ")
        t_fmt = tactic_str
        if len(t_parts) > 1:
            t_fmt = t_parts[0] + "\n" + " ".join(t_parts[1:])
        
        ts = G.nodes[n]["ts"]
        
        # Top label (IPs)
        ip_label = f"Src: {src}\nDst: {dst}"
        ax.text(pos[n][0], pos[n][1] + 0.3, ip_label, ha="center", va="bottom", fontsize=9, 
                fontweight="normal", color="#1e293b", 
                bbox=dict(facecolor='#ffffff', edgecolor='#cbd5e1', boxstyle='round,pad=0.4', alpha=0.9))
                
        # Bottom label (Tactic & Timestamp)
        bottom_label = f"{t_fmt}\n\n[ {ts} ]"
        ax.text(pos[n][0], pos[n][1] - 0.28, bottom_label, ha="center", va="top", fontsize=10, 
                fontweight="bold", color="#0f172a")
        
    # Draw step numbers inside nodes
    labels = {n: str(n - min([k for k,v in G.nodes(data=True) if v['chain_id'] == G.nodes[n]['chain_id']]) + 1) for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels, font_size=14, font_color="#ffffff", font_weight="bold")
    
    # Add legend
    handles = [Line2D([0],[0], color="#3b82f6", lw=3.0, label="Temporal Progression Sequence")]
    ax.legend(handles=handles, loc="upper right", fontsize=11, framealpha=1.0, edgecolor="#000000")
    
    ax.set_title("MITRE-CORE Alert Correlation: Multiple Parallel Attack Chains (NSL-KDD)", fontsize=16, fontweight="bold", color="#000000", pad=20)
    
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

pattern = re.compile(r"def fig1_attack_graph\(\):.*?return out", re.DOTALL)
code = pattern.sub(new_func, code)

with open("experiments/generate_figures.py", "w", encoding="utf-8") as f:
    f.write(code)
