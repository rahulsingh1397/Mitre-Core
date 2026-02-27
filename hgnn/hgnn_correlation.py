"""
MITRE-CORE HGNN Module
Heterogeneous Graph Neural Network for Advanced Alert Correlation

Replaces Union-Find correlation with learned graph embeddings.
Based on research: "On the Use of HGNNs for Detecting APTs" (ACM 2024)

Architecture:
- Heterogeneous Graph Attention Network (HAN/HGT) 
- Multi-relation edges: shares_ip, shares_host, temporal_near, user_to_alert, host_to_alert
- Learns optimal feature weights automatically vs handcrafted 0.6/0.3/0.1
- O(n+e) complexity vs O(n²) for Union-Find
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import HeteroConv, GATConv, Linear, global_mean_pool
from torch_geometric.data import HeteroData
from typing import Dict, List, Tuple, Optional
import pandas as pd
import numpy as np
from collections import defaultdict
import logging

logger = logging.getLogger("mitre-core.hgnn")


class HomogeneousGNN(nn.Module):
    """
    Homogeneous GNN Baseline (GCN) for comparison against HGNN.
    Treats all nodes as 'alerts' and projects entity features into alert space
    or creates generic edges between alerts based on shared entities.
    """
    def __init__(
        self,
        input_dim: int = 8,
        feature_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
        num_clusters: int = 10
    ):
        super().__init__()
        from torch_geometric.nn import GCNConv
        
        self.encoder = nn.Linear(input_dim, feature_dim)
        
        self.convs = nn.ModuleList()
        for i in range(num_layers):
            in_dim = feature_dim if i == 0 else hidden_dim
            self.convs.append(GCNConv(in_dim, hidden_dim))
            
        self.dropout = dropout
        
        self.cluster_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_clusters)
        )
        
    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        x = self.encoder(x)
        
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            if i < len(self.convs) - 1:
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
                
        cluster_logits = self.cluster_classifier(x)
        return cluster_logits, x

class MITREHeteroGNN(nn.Module):
    """
    Heterogeneous Graph Neural Network for MITRE-CORE.
    
    Node Types:
    - alert: Security alerts (main entity)
    - user: Source/destination users  
    - host: Source/destination/device hosts
    - ip: IP addresses (source/destination/device)
    
    Edge Types:
    - alert-shares_ip-alert: Alerts sharing IP addresses
    - alert-shares_host-alert: Alerts sharing hostnames
    - alert-temporal_near-alert: Alerts within time window
    - user-owns-alert: User associated with alert
    - host-generates-alert: Host associated with alert
    - ip-involved_in-alert: IP involved in alert
    """
    
    def __init__(
        self,
        alert_feature_dim: int = 64,
        user_feature_dim: int = 32,
        host_feature_dim: int = 32,
        ip_feature_dim: int = 32,
        hidden_dim: int = 128,
        num_heads: int = 4,
        num_layers: int = 2,
        dropout: float = 0.3,
        num_clusters: int = 10  # Max expected clusters (dynamic expansion supported)
    ):
        super().__init__()
        
        self.alert_feature_dim = alert_feature_dim
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        
        # Input projections (normalize different feature dimensions to hidden_dim)
        self.alert_encoder = Linear(-1, hidden_dim)
        self.user_encoder = Linear(-1, hidden_dim)
        self.host_encoder = Linear(-1, hidden_dim)
        self.ip_encoder = Linear(-1, hidden_dim)
        
        # Heterogeneous GNN layers
        self.convs = nn.ModuleList()
        
        for layer in range(num_layers):
            # Define edge types and their convolution operators
            conv_dict = {}
            
            # Alert-to-Alert edges (intra-type)
            conv_dict[('alert', 'shares_ip', 'alert')] = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                add_self_loops=False
            )
            conv_dict[('alert', 'shares_host', 'alert')] = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                add_self_loops=False
            )
            conv_dict[('alert', 'temporal_near', 'alert')] = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                add_self_loops=False
            )
            
            # Cross-type edges (alert to other entities)
            conv_dict[('user', 'owns', 'alert')] = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                add_self_loops=False
            )
            conv_dict[('alert', 'owned_by', 'user')] = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                add_self_loops=False
            )
            
            conv_dict[('host', 'generates', 'alert')] = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                add_self_loops=False
            )
            conv_dict[('alert', 'generated_by', 'host')] = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                add_self_loops=False
            )
            
            conv_dict[('ip', 'involved_in', 'alert')] = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                add_self_loops=False
            )
            conv_dict[('alert', 'involves', 'ip')] = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                add_self_loops=False
            )
            
            # Create heterogeneous convolution layer
            hetero_conv = HeteroConv(conv_dict, aggr='mean')
            self.convs.append(hetero_conv)
        
        # Cluster classification head
        self.cluster_classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_clusters)
        )
        
        # Attention weights visualization (for interpretability)
        self.attention_weights = {}
        
    def forward(self, data: HeteroData) -> Tuple[torch.Tensor, Dict[str, torch.Tensor]]:
        """
        Forward pass through HGNN.
        
        Args:
            data: HeteroData with node features and edge indices
            
        Returns:
            cluster_logits: [num_alerts, num_clusters] cluster assignment probabilities
            node_embeddings: Dict of embeddings for each node type
        """
        # Encode node features for available node types only
        x_dict = {}
        node_types = data.node_types  # Proper way to get node types in PyG
        
        if 'alert' in node_types:
            x_dict['alert'] = self.alert_encoder(data['alert'].x)
        if 'user' in node_types:
            x_dict['user'] = self.user_encoder(data['user'].x)
        if 'host' in node_types:
            x_dict['host'] = self.host_encoder(data['host'].x)
        if 'ip' in node_types:
            x_dict['ip'] = self.ip_encoder(data['ip'].x)
        
        if 'alert' not in x_dict:
            raise ValueError("Data must contain 'alert' nodes")
        
        # Filter edge_index_dict to only include edges for available node types
        available_edge_index_dict = {}
        for edge_type, edge_index in data.edge_index_dict.items():
            src, rel, dst = edge_type
            # Only include edges where both src and dst node types exist
            if src in x_dict and dst in x_dict:
                available_edge_index_dict[edge_type] = edge_index
        
        # Message passing through heterogeneous layers
        for i, conv in enumerate(self.convs):
            # Only pass edges and nodes that exist in this conv's configuration
            conv_edge_index_dict = {}
            for edge_type in conv.convs.keys():
                if edge_type in available_edge_index_dict:
                    conv_edge_index_dict[edge_type] = available_edge_index_dict[edge_type]
            
            if len(conv_edge_index_dict) == 0:
                # No edges for this layer, skip
                continue
                
            x_dict = conv(x_dict, conv_edge_index_dict)
            
            # Apply activation and dropout (except last layer)
            if i < len(self.convs) - 1:
                x_dict = {key: F.relu(x) for key, x in x_dict.items()}
                x_dict = {key: F.dropout(x, p=0.3, training=self.training) 
                         for key, x in x_dict.items()}
        
        # Cluster classification on alert embeddings
        alert_embeddings = x_dict['alert']
        cluster_logits = self.cluster_classifier(alert_embeddings)
        
        return cluster_logits, x_dict
    
    def get_attention_weights(self, data: HeteroData) -> Dict[str, torch.Tensor]:
        """
        Extract attention weights for interpretability.
        Shows which edge types contributed most to clustering decisions.
        """
        self.eval()
        attention_weights = {}
        
        with torch.no_grad():
            # Forward pass with attention extraction
            x_dict = {
                'alert': self.alert_encoder(data['alert'].x),
                'user': self.user_encoder(data['user'].x) if 'user' in data else None,
                'host': self.host_encoder(data['host'].x) if 'host' in data else None,
                'ip': self.ip_encoder(data['ip'].x) if 'ip' in data else None
            }
            x_dict = {k: v for k, v in x_dict.items() if v is not None}
            
            for conv in self.convs:
                x_dict, attn = conv(x_dict, data.edge_index_dict, return_attention_weights=True)
                attention_weights.update(attn)
        
        return attention_weights


class AlertToGraphConverter:
    """
    Converts MITRE-CORE alert DataFrame to PyTorch Geometric HeteroData.
    
    Handles:
    - Node creation (alerts, users, hosts, IPs)
    - Edge construction (shares_ip, shares_host, temporal_near)
    - Feature encoding (categorical to numeric)
    - Temporal edge weighting
    """
    
    def __init__(self, temporal_window_hours: float = 1.0):
        self.temporal_window = temporal_window_hours
        
    def convert(self, df: pd.DataFrame) -> HeteroData:
        """
        Convert alert DataFrame to heterogeneous graph.
        
        Args:
            df: DataFrame with columns:
                AlertId, SourceAddress, DestinationAddress, DeviceAddress,
                SourceUserName, SourceHostName, DeviceHostName, DestinationHostName,
                MalwareIntelAttackType, AttackSeverity, EndDate
                
        Returns:
            HeteroData object ready for HGNN processing
        """
        data = HeteroData()
        
        # Extract unique entities
        alerts = df['AlertId'].unique()
        users = pd.concat([
            df['SourceUserName'].dropna(),
        ]).unique()
        hosts = pd.concat([
            df['SourceHostName'].dropna(),
            df['DeviceHostName'].dropna(),
            df['DestinationHostName'].dropna()
        ]).unique()
        ips = pd.concat([
            df['SourceAddress'].dropna(),
            df['DestinationAddress'].dropna(),
            df['DeviceAddress'].dropna()
        ]).unique()
        
        # Create node index mappings
        alert_to_idx = {a: i for i, a in enumerate(alerts)}
        user_to_idx = {u: i for i, u in enumerate(users)}
        host_to_idx = {h: i for i, h in enumerate(hosts)}
        ip_to_idx = {ip: i for i, ip in enumerate(ips)}
        
        # Encode alert features
        alert_features = self._encode_alert_features(df)
        data['alert'].x = torch.tensor(alert_features, dtype=torch.float)
        
        # Encode entity features (simple one-hot or embeddings)
        if len(users) > 0:
            data['user'].x = torch.eye(len(users))  # Identity features, learned by GNN
        if len(hosts) > 0:
            data['host'].x = torch.eye(len(hosts))
        if len(ips) > 0:
            data['ip'].x = torch.eye(len(ips))
        
        # Build edges
        edges = self._build_edges(df, alert_to_idx, user_to_idx, host_to_idx, ip_to_idx)
        
        for edge_type, (src, dst) in edges.items():
            if len(src) > 0:
                data[edge_type].edge_index = torch.tensor([src, dst], dtype=torch.long)
        
        return data
    
    def _encode_alert_features(self, df: pd.DataFrame) -> np.ndarray:
        """Encode alert features to numeric vectors."""
        features = []
        
        # Attack type encoding (one-hot or label)
        attack_types = pd.Categorical(df['MalwareIntelAttackType']).codes
        
        # Severity encoding
        severity_map = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
        severities = df['AttackSeverity'].map(severity_map).fillna(1).values
        
        # Temporal features (hour of day, day of week)
        df['EndDate'] = pd.to_datetime(df['EndDate'])
        hour = df['EndDate'].dt.hour.values
        day_of_week = df['EndDate'].dt.dayofweek.values
        
        # Combine features
        features = np.column_stack([
            attack_types,
            severities,
            hour / 23.0,  # Normalize
            day_of_week / 6.0
        ])
        
        return features
    
    def _build_edges(
        self, 
        df: pd.DataFrame,
        alert_to_idx: Dict,
        user_to_idx: Dict,
        host_to_idx: Dict,
        ip_to_idx: Dict
    ) -> Dict[str, Tuple[List, List]]:
        """Build heterogeneous edges between nodes."""
        
        edges = defaultdict(lambda: ([], []))
        
        # Alert-to-Alert edges based on shared IPs
        ip_to_alerts = defaultdict(list)
        for idx, row in df.iterrows():
            alert_id = row['AlertId']
            for col in ['SourceAddress', 'DestinationAddress', 'DeviceAddress']:
                if pd.notna(row[col]):
                    ip_to_alerts[row[col]].append(alert_to_idx[alert_id])
        
        for ip, alert_indices in ip_to_alerts.items():
            for i, alert_i in enumerate(alert_indices):
                for alert_j in alert_indices[i+1:]:
                    edges[('alert', 'shares_ip', 'alert')][0].append(alert_i)
                    edges[('alert', 'shares_ip', 'alert')][1].append(alert_j)
                    # Undirected: add reverse
                    edges[('alert', 'shares_ip', 'alert')][0].append(alert_j)
                    edges[('alert', 'shares_ip', 'alert')][1].append(alert_i)
        
        # Alert-to-Alert edges based on shared hosts
        host_to_alerts = defaultdict(list)
        for idx, row in df.iterrows():
            alert_id = row['AlertId']
            for col in ['SourceHostName', 'DeviceHostName', 'DestinationHostName']:
                if pd.notna(row[col]):
                    host_to_alerts[row[col]].append(alert_to_idx[alert_id])
        
        for host, alert_indices in host_to_alerts.items():
            for i, alert_i in enumerate(alert_indices):
                for alert_j in alert_indices[i+1:]:
                    edges[('alert', 'shares_host', 'alert')][0].append(alert_i)
                    edges[('alert', 'shares_host', 'alert')][1].append(alert_j)
                    edges[('alert', 'shares_host', 'alert')][0].append(alert_j)
                    edges[('alert', 'shares_host', 'alert')][1].append(alert_i)
        
        # Temporal edges (within time window)
        df_sorted = df.sort_values('EndDate')
        timestamps = pd.to_datetime(df_sorted['EndDate'])
        alert_indices = [alert_to_idx[a] for a in df_sorted['AlertId']]
        
        for i, (idx_i, ts_i) in enumerate(zip(alert_indices, timestamps)):
            for j in range(i+1, len(alert_indices)):
                ts_j = timestamps.iloc[j]
                time_diff = abs((ts_j - ts_i).total_seconds() / 3600)
                
                if time_diff <= self.temporal_window:
                    edges[('alert', 'temporal_near', 'alert')][0].append(idx_i)
                    edges[('alert', 'temporal_near', 'alert')][1].append(alert_indices[j])
                    edges[('alert', 'temporal_near', 'alert')][0].append(alert_indices[j])
                    edges[('alert', 'temporal_near', 'alert')][1].append(idx_i)
                else:
                    break  # Sorted, so further alerts will be farther in time
        
        # Cross-type edges: Alert to User/Host/IP
        for idx, row in df.iterrows():
            alert_idx = alert_to_idx[row['AlertId']]
            
            # User edges
            if pd.notna(row['SourceUserName']) and row['SourceUserName'] in user_to_idx:
                user_idx = user_to_idx[row['SourceUserName']]
                edges[('user', 'owns', 'alert')][0].append(user_idx)
                edges[('user', 'owns', 'alert')][1].append(alert_idx)
                edges[('alert', 'owned_by', 'user')][0].append(alert_idx)
                edges[('alert', 'owned_by', 'user')][1].append(user_idx)
            
            # Host edges
            for col in ['SourceHostName', 'DeviceHostName', 'DestinationHostName']:
                if pd.notna(row[col]) and row[col] in host_to_idx:
                    host_idx = host_to_idx[row[col]]
                    edges[('host', 'generates', 'alert')][0].append(host_idx)
                    edges[('host', 'generates', 'alert')][1].append(alert_idx)
                    edges[('alert', 'generated_by', 'host')][0].append(alert_idx)
                    edges[('alert', 'generated_by', 'host')][1].append(host_idx)
            
            # IP edges
            for col in ['SourceAddress', 'DestinationAddress', 'DeviceAddress']:
                if pd.notna(row[col]) and row[col] in ip_to_idx:
                    ip_idx = ip_to_idx[row[col]]
                    edges[('ip', 'involved_in', 'alert')][0].append(ip_idx)
                    edges[('ip', 'involved_in', 'alert')][1].append(alert_idx)
                    edges[('alert', 'involves', 'ip')][0].append(alert_idx)
                    edges[('alert', 'involves', 'ip')][1].append(ip_idx)
        
        return dict(edges)


class HGNNCorrelationEngine:
    """
    Drop-in replacement for Union-Find correlation engine.
    Uses HGNN for alert correlation and clustering.
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        hidden_dim: int = 128,
        num_heads: int = 4,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        temperature: float = 1.0
    ):
        self.device = device
        self.converter = AlertToGraphConverter()
        self.temperature = temperature  # Temperature scaling for confidence calibration
        
        # Initialize model
        self.model = MITREHeteroGNN(
            hidden_dim=hidden_dim,
            num_heads=num_heads
        ).to(device)
        
        # Load pretrained weights if available
        if model_path and torch.cuda.is_available():
            self.model.load_state_dict(torch.load(model_path))
            logger.info(f"Loaded HGNN model from {model_path}")
        
        self.model.eval()

    def calibrate_temperature(self, logits: torch.Tensor, labels: torch.Tensor,
                               lr: float = 0.01, max_iter: int = 50) -> float:
        """
        Learn optimal temperature using NLL minimization on a validation set.
        Implements Platt/Guo et al. temperature scaling (ICML 2017).

        Args:
            logits: Raw model logits [N, C]
            labels: Ground-truth cluster indices [N]
            lr: Learning rate for temperature optimizer
            max_iter: Maximum optimization iterations

        Returns:
            Optimal temperature value
        """
        temperature = nn.Parameter(torch.ones(1, device=self.device))
        optimizer = torch.optim.LBFGS([temperature], lr=lr, max_iter=max_iter)

        def eval_nll():
            optimizer.zero_grad()
            scaled = logits / temperature.clamp(min=1e-6)
            loss = F.cross_entropy(scaled, labels)
            loss.backward()
            return loss

        optimizer.step(eval_nll)
        optimal_temp = float(temperature.item())
        logger.info(f"Temperature calibration: T={optimal_temp:.4f}")
        self.temperature = optimal_temp
        return optimal_temp

    def _apply_temperature(self, logits: torch.Tensor) -> torch.Tensor:
        """Apply temperature scaling to logits before softmax."""
        return logits / max(self.temperature, 1e-6)

    def correlate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Correlate alerts using HGNN instead of Union-Find.
        
        Args:
            df: Alert DataFrame
            
        Returns:
            DataFrame with 'pred_cluster' column (HGNN cluster assignments)
        """
        logger.info(f"Building heterogeneous graph from {len(df)} alerts...")
        
        # Convert to graph
        data = self.converter.convert(df)
        data = data.to(self.device)
        
        logger.info(f"Graph: {data['alert'].x.shape[0]} alerts, "
                   f"{len(data.edge_types)} edge types")
        
        # HGNN inference
        with torch.no_grad():
            cluster_logits, embeddings = self.model(data)
            cluster_assignments = torch.argmax(cluster_logits, dim=1).cpu().numpy()
            
            # Get confidence scores with temperature scaling calibration
            calibrated_logits = self._apply_temperature(cluster_logits)
            confidences = torch.softmax(calibrated_logits, dim=1).max(dim=1)[0].cpu().numpy()
            raw_confidences = torch.softmax(cluster_logits, dim=1).max(dim=1)[0].cpu().numpy()
        
        # Add predictions to DataFrame
        df_result = df.copy()
        df_result['pred_cluster'] = cluster_assignments
        df_result['cluster_confidence'] = confidences
        df_result['cluster_confidence_raw'] = raw_confidences
        df_result['hgnn_embedding'] = list(embeddings['alert'].cpu().numpy())
        
        # Log statistics
        num_clusters = len(np.unique(cluster_assignments))
        logger.info(f"HGNN assigned alerts to {num_clusters} clusters")
        logger.info(f"Average calibrated confidence: {confidences.mean():.3f} "
                    f"(raw: {raw_confidences.mean():.3f}, T={self.temperature:.3f})")
        
        return df_result
    
    def get_attention_analysis(self, df: pd.DataFrame) -> Dict:
        """
        Analyze which edge types contributed most to clustering.
        For interpretability and debugging.
        """
        data = self.converter.convert(df)
        data = data.to(self.device)
        
        attention_weights = self.model.get_attention_weights(data)
        
        # Aggregate attention by edge type
        analysis = {}
        for edge_type, attn in attention_weights.items():
            analysis[str(edge_type)] = {
                'mean_attention': float(attn.mean()),
                'max_attention': float(attn.max()),
                'attention_std': float(attn.std()),
            }
        
        return analysis
    
    def save_model(self, path: str):
        """Save trained model weights."""
        torch.save(self.model.state_dict(), path)
        logger.info(f"Saved HGNN model to {path}")


# ============================================================================
# Training Components (for self-supervised pre-training)
# ============================================================================

class ContrastiveAlertLearner(nn.Module):
    """
    Self-supervised contrastive learning for alert embeddings.
    Learns from unlabeled alert data (most real-world data is unlabeled).
    Based on CARLA: Self-Supervised Contrastive Representation Learning (2023-2024)
    """
    
    def __init__(self, hgnn: MITREHeteroGNN, temperature: float = 0.5):
        super().__init__()
        self.hgnn = hgnn
        self.temperature = temperature
        
    def forward(self, data1: HeteroData, data2: HeteroData) -> torch.Tensor:
        """
        Contrastive loss between two augmented views of same graph.
        
        Args:
            data1: First augmented view
            data2: Second augmented view
            
        Returns:
            Contrastive loss (NT-Xent)
        """
        # Get embeddings for both views
        _, embeddings1 = self.hgnn(data1)
        _, embeddings2 = self.hgnn(data2)
        
        z1 = F.normalize(embeddings1['alert'], dim=1)
        z2 = F.normalize(embeddings2['alert'], dim=1)
        
        # Compute similarity matrix
        similarity_matrix = torch.mm(z1, z2.t()) / self.temperature
        
        # Labels: diagonal elements are positives
        labels = torch.arange(z1.size(0), device=z1.device)
        
        # NT-Xent loss
        loss = F.cross_entropy(similarity_matrix, labels)
        
        return loss


class GraphAugmenter:
    """
    Data augmentation for contrastive learning on alert graphs.
    """
    
    @staticmethod
    def drop_edges(data: HeteroData, drop_prob: float = 0.1) -> HeteroData:
        """Randomly drop edges to create augmented view."""
        data_aug = data.clone()
        
        for edge_type in data_aug.edge_types:
            edge_index = data_aug[edge_type].edge_index
            num_edges = edge_index.size(1)
            mask = torch.rand(num_edges) > drop_prob
            data_aug[edge_type].edge_index = edge_index[:, mask]
        
        return data_aug
    
    @staticmethod
    def mask_features(data: HeteroData, mask_prob: float = 0.1) -> HeteroData:
        """Randomly mask node features."""
        data_aug = data.clone()
        
        if 'alert' in data_aug:
            x = data_aug['alert'].x.clone()
            mask = torch.rand(x.shape) < mask_prob
            x[mask] = 0  # or replace with mean
            data_aug['alert'].x = x
        
        return data_aug


if __name__ == "__main__":
    # Example usage
    print("MITRE-CORE HGNN Module")
    print("=" * 50)
    print("Usage:")
    print("  from hgnn_correlation import HGNNCorrelationEngine")
    print("  engine = HGNNCorrelationEngine()")
    print("  result_df = engine.correlate(alert_dataframe)")
    print()
    print("For training:")
    print("  Use ContrastiveAlertLearner with GraphAugmenter")
