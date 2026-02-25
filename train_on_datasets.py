"""
Train HGNN on Public Datasets
Trains the HGNN model using downloaded public cybersecurity datasets
"""

import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre-core.train_hgnn")

import torch
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Optional, List, Tuple
from sklearn.model_selection import train_test_split
from torch_geometric.loader import DataLoader
import warnings
warnings.filterwarnings('ignore')

# Import PyTorch Geometric
try:
    from torch_geometric.data import HeteroData
except ImportError:
    logger.error("torch_geometric not installed")
    sys.exit(1)

# Import HGNN modules
try:
    from hgnn_correlation import (
        MITREHeteroGNN, AlertToGraphConverter, 
        HGNNCorrelationEngine, ContrastiveAlertLearner
    )
    from hgnn_training import HGNNTrainer, AlertGraphDataset
    HGNN_AVAILABLE = True
except ImportError as e:
    logger.error(f"HGNN modules not available: {e}")
    HGNN_AVAILABLE = False
    sys.exit(1)


class PublicDatasetGraphConverter:
    """
    Converts public datasets in MITRE format to PyTorch Geometric HeteroData.
    Handles the converted column names from UNSW-NB15, CIC-IDS-2017, etc.
    """
    
    def __init__(self, temporal_window_hours: float = 1.0):
        self.temporal_window = temporal_window_hours
        
    def convert(self, df: pd.DataFrame) -> HeteroData:
        """Convert MITRE-format DataFrame to heterogeneous graph."""
        from torch_geometric.data import HeteroData
        import torch
        from collections import defaultdict
        
        data = HeteroData()
        
        # Generate AlertId if not present
        if 'AlertId' not in df.columns:
            df = df.copy()
            df['AlertId'] = [f"alert_{i}" for i in range(len(df))]
        
        # Extract unique entities
        alerts = df['AlertId'].unique()
        
        # Users from username column
        if 'username' in df.columns:
            users = df['username'].dropna().unique()
        else:
            users = []
        
        # Hosts from hostname column
        if 'hostname' in df.columns:
            hosts = df['hostname'].dropna().unique()
        else:
            hosts = []
        
        # IPs from src_ip and dst_ip
        ips = []
        if 'src_ip' in df.columns:
            ips.extend(df['src_ip'].dropna().unique())
        if 'dst_ip' in df.columns:
            ips.extend(df['dst_ip'].dropna().unique())
        ips = list(set(ips))
        
        # Create node index mappings
        alert_to_idx = {a: i for i, a in enumerate(alerts)}
        user_to_idx = {u: i for i, u in enumerate(users)} if len(users) > 0 else {}
        host_to_idx = {h: i for i, h in enumerate(hosts)} if len(hosts) > 0 else {}
        ip_to_idx = {ip: i for i, ip in enumerate(ips)} if len(ips) > 0 else {}
        
        # Encode alert features
        alert_features = self._encode_alert_features(df)
        data['alert'].x = torch.tensor(alert_features, dtype=torch.float)
        
        # Encode entity features
        if len(users) > 0:
            data['user'].x = torch.eye(len(users))
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
        
        # Tactic encoding
        if 'tactic' in df.columns:
            tactics = pd.Categorical(df['tactic']).codes
        else:
            tactics = np.zeros(len(df))
        
        # Alert type encoding (attack=1, normal=0)
        if 'alert_type' in df.columns:
            alert_types = (df['alert_type'] == 'attack').astype(int).values
        else:
            alert_types = np.zeros(len(df))
        
        # Temporal features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            hour = df['timestamp'].dt.hour.values
            day_of_week = df['timestamp'].dt.dayofweek.values
        else:
            hour = np.zeros(len(df))
            day_of_week = np.zeros(len(df))
        
        # Protocol encoding
        if 'protocol' in df.columns:
            protocols = pd.Categorical(df['protocol']).codes
        else:
            protocols = np.zeros(len(df))
        
        # Service encoding
        if 'service' in df.columns:
            services = pd.Categorical(df['service']).codes
        else:
            services = np.zeros(len(df))
        
        # Combine features
        features = np.column_stack([
            tactics,
            alert_types,
            hour / 23.0,
            day_of_week / 6.0,
            protocols,
            services
        ])
        
        return features
    
    def _build_edges(self, df, alert_to_idx, user_to_idx, host_to_idx, ip_to_idx):
        """Build heterogeneous edges between nodes."""
        from collections import defaultdict
        edges = defaultdict(lambda: ([], []))
        
        # Add AlertId if missing
        if 'AlertId' not in df.columns:
            df = df.copy()
            df['AlertId'] = [f"alert_{i}" for i in range(len(df))]
        
        # Alert-to-Alert edges based on shared IPs
        ip_to_alerts = defaultdict(list)
        for idx, row in df.iterrows():
            alert_id = row['AlertId']
            if 'src_ip' in df.columns and pd.notna(row.get('src_ip')):
                ip_to_alerts[row['src_ip']].append(alert_to_idx[alert_id])
            if 'dst_ip' in df.columns and pd.notna(row.get('dst_ip')):
                ip_to_alerts[row['dst_ip']].append(alert_to_idx[alert_id])
        
        for ip, alert_indices in ip_to_alerts.items():
            for i, alert_i in enumerate(alert_indices):
                for alert_j in alert_indices[i+1:]:
                    edges[('alert', 'shares_ip', 'alert')][0].append(alert_i)
                    edges[('alert', 'shares_ip', 'alert')][1].append(alert_j)
                    edges[('alert', 'shares_ip', 'alert')][0].append(alert_j)
                    edges[('alert', 'shares_ip', 'alert')][1].append(alert_i)
        
        # Alert-to-User edges
        if 'username' in df.columns:
            for idx, row in df.iterrows():
                if pd.notna(row.get('username')) and row['username'] in user_to_idx:
                    alert_idx = alert_to_idx[row['AlertId']]
                    user_idx = user_to_idx[row['username']]
                    edges[('user', 'owns', 'alert')][0].append(user_idx)
                    edges[('user', 'owns', 'alert')][1].append(alert_idx)
        
        # Alert-to-Host edges
        if 'hostname' in df.columns:
            for idx, row in df.iterrows():
                if pd.notna(row.get('hostname')) and row['hostname'] in host_to_idx:
                    alert_idx = alert_to_idx[row['AlertId']]
                    host_idx = host_to_idx[row['hostname']]
                    edges[('host', 'generates', 'alert')][0].append(host_idx)
                    edges[('host', 'generates', 'alert')][1].append(alert_idx)
        
        return edges


class DatasetTrainer:
    """Train HGNN on downloaded public datasets."""
    
    def __init__(self, dataset_path: str = "./datasets", output_path: str = "./hgnn_checkpoints"):
        self.dataset_path = Path(dataset_path)
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"Using device: {self.device}")
    
    def load_mitre_dataset(self, dataset_name: str) -> Optional[pd.DataFrame]:
        """Load a dataset in MITRE-CORE format."""
        filepath = self.dataset_path / dataset_name / "mitre_format.csv"
        
        if not filepath.exists():
            logger.error(f"Dataset not found: {filepath}")
            return None
        
        logger.info(f"Loading {dataset_name} from {filepath}")
        df = pd.read_csv(filepath)
        logger.info(f"Loaded {len(df)} alerts")
        
        # Convert timestamp
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        return df
    
    def prepare_training_data(self, df: pd.DataFrame, test_size: float = 0.2) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
        """
        Prepare training data with ground truth labels.
        
        For public datasets, we use attack category as campaign/cluster label.
        """
        # Filter out normal traffic for training (we want to cluster attacks)
        attack_df = df[df['alert_type'] == 'attack'].copy()
        
        if len(attack_df) == 0:
            logger.warning("No attack alerts found, using all data")
            attack_df = df.copy()
        
        logger.info(f"Using {len(attack_df)} alerts for training")
        
        # Group by campaign_id (ground truth clusters)
        # Each unique campaign_id represents a different attack campaign
        ground_truth = attack_df['campaign_id'].values
        
        # Split into train/test
        train_df, test_df, train_labels, test_labels = train_test_split(
            attack_df, ground_truth, 
            test_size=test_size, 
            random_state=42,
            stratify=ground_truth  # Maintain class distribution
        )
        
        logger.info(f"Train: {len(train_df)}, Test: {len(test_df)}")
        logger.info(f"Train campaigns: {len(np.unique(train_labels))}")
        logger.info(f"Test campaigns: {len(np.unique(test_labels))}")
        
        return train_df, test_df, pd.Series(train_labels), pd.Series(test_labels)
    
    def train_on_dataset(self, dataset_name: str, epochs: int = 50, contrastive_epochs: int = 20) -> Optional[str]:
        """Train HGNN on a specific dataset."""
        logger.info(f"\n{'='*60}")
        logger.info(f"Training on {dataset_name}")
        logger.info(f"{'='*60}")
        
        # Load data
        df = self.load_mitre_dataset(dataset_name)
        if df is None:
            return None
        
        # Prepare train/test split
        train_df, test_df, train_labels, test_labels = self.prepare_training_data(df)
        
        # Create graph datasets
        logger.info("\nConverting alerts to graphs...")
        
        # Use alert features for node encoding
        usernames = train_df.get('username', pd.Series(['unknown'] * len(train_df)))
        addresses = train_df.get('src_ip', pd.Series(['0.0.0.0'] * len(train_df)))
        
        # Build converter for public dataset format
        converter = PublicDatasetGraphConverter()
        
        # Convert to HeteroData graphs
        train_graphs = []
        train_labels_list = []
        
        # Group alerts into synthetic "campaigns" for training
        # We'll create mini-campaigns of 5-15 alerts each
        campaign_size = 10
        num_campaigns = len(train_df) // campaign_size
        
        logger.info(f"Creating {num_campaigns} mini-campaigns for training...")
        
        for i in range(0, min(len(train_df), num_campaigns * campaign_size), campaign_size):
            end_idx = min(i + campaign_size, len(train_df))
            mini_df = train_df.iloc[i:end_idx]
            mini_usernames = usernames.iloc[i:end_idx]
            mini_addresses = addresses.iloc[i:end_idx]
            
            # Build graph for this mini-campaign
            graph = converter.convert(mini_df)
            
            if graph is not None and 'alert' in graph.node_types:
                train_graphs.append(graph)
                # Use the most common campaign_id as label
                campaign_ids = train_df.iloc[i:end_idx]['campaign_id'].values
                label = int(np.bincount(campaign_ids.astype(int)).argmax())
                train_labels_list.append(label)
        
        logger.info(f"Created {len(train_graphs)} training graphs")
        
        if len(train_graphs) == 0:
            logger.error("No valid training graphs created")
            return None
        
        # Create test graphs
        test_graphs = []
        test_labels_list = []
        
        for i in range(0, min(len(test_df), num_campaigns * campaign_size), campaign_size):
            end_idx = min(i + campaign_size, len(test_df))
            mini_df = test_df.iloc[i:end_idx]
            mini_usernames = test_df.get('username', pd.Series(['unknown'] * len(test_df))).iloc[i:end_idx]
            mini_addresses = test_df.get('src_ip', pd.Series(['0.0.0.0'] * len(test_df))).iloc[i:end_idx]
            
            graph = converter.convert(mini_df)
            
            if graph is not None and 'alert' in graph.node_types:
                test_graphs.append(graph)
                campaign_ids = test_df.iloc[i:end_idx]['campaign_id'].values
                label = int(np.bincount(campaign_ids.astype(int)).argmax())
                test_labels_list.append(label)
        
        logger.info(f"Created {len(test_graphs)} test graphs")
        
        # Ensure all graphs have consistent node types
        train_graphs = self._ensure_consistent_node_types(train_graphs)
        test_graphs = self._ensure_consistent_node_types(test_graphs)
        
        # Create model
        alert_feature_dim = 64
        hidden_dim = 128
        num_clusters = max(len(np.unique(np.concatenate([train_labels_list, test_labels_list]))), 10)
        
        logger.info(f"Model config: hidden_dim={hidden_dim}, num_clusters={num_clusters}")
        
        model = MITREHeteroGNN(
            alert_feature_dim=alert_feature_dim,
            hidden_dim=hidden_dim,
            num_clusters=num_clusters
        ).to(self.device)
        
        # Create trainer
        trainer = HGNNTrainer(
            model=model,
            device=self.device,
            learning_rate=0.001,
            weight_decay=1e-5
        )
        
        # Create contrastive dataset (self-supervised)
        logger.info(f"\nPhase 1: Contrastive Pre-training ({contrastive_epochs} epochs)")
        
        # Contrastive learning - use graphs directly
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        
        from hgnn_correlation import ContrastiveAlertLearner
        contrastive_learner = ContrastiveAlertLearner(model)
        
        for epoch in range(contrastive_epochs):
            model.train()
            total_loss = 0
            
            for graph in train_graphs[:1000]:  # Use subset for speed
                optimizer.zero_grad()
                
                # Create two augmented views
                graph = graph.to(self.device)
                
                # Forward pass
                z1, _ = model(graph)
                z2, _ = model(graph)  # Same graph (simplified)
                
                # Contrastive loss (simplified - just use representation similarity)
                loss = torch.mean(torch.pow(z1 - z2, 2))
                
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
            
            if (epoch + 1) % 5 == 0:
                avg_loss = total_loss / min(len(train_graphs), 1000)
                logger.info(f"Epoch {epoch+1}/{contrastive_epochs}, Loss: {avg_loss:.4f}")
        
        # Supervised fine-tuning
        logger.info(f"\nPhase 2: Supervised Fine-tuning ({epochs} epochs)")
        
        # Prepare supervised data
        supervised_graphs = []
        for i, graph in enumerate(train_graphs):
            # Add cluster labels to graph
            if 'alert' in graph:
                num_alerts = graph['alert'].x.shape[0]
                # Assign same campaign label to all alerts in this mini-campaign
                graph.campaign_labels = torch.full((num_alerts,), train_labels_list[i], dtype=torch.long)
            supervised_graphs.append(graph)
        
        # Fine-tune
        optimizer = torch.optim.Adam(model.parameters(), lr=0.0005)
        
        best_loss = float('inf')
        best_model_path = None
        
        for epoch in range(epochs):
            model.train()
            total_loss = 0
            
            for graph in supervised_graphs:
                optimizer.zero_grad()
                
                # Forward pass
                graph = graph.to(self.device)
                cluster_logits, _ = model(graph)
                
                # Loss: classify each alert to campaign
                if hasattr(graph, 'campaign_labels'):
                    labels = graph.campaign_labels.to(self.device)
                    loss = torch.nn.functional.cross_entropy(cluster_logits, labels)
                    
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
            
            avg_loss = total_loss / len(supervised_graphs)
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")
            
            # Save best model
            if avg_loss < best_loss:
                best_loss = avg_loss
                best_model_path = self.output_path / f"{dataset_name}_best.pt"
                torch.save({
                    'epoch': epoch,
                    'model_state_dict': model.state_dict(),
                    'optimizer_state_dict': optimizer.state_dict(),
                    'loss': best_loss,
                    'num_clusters': num_clusters,
                    'hidden_dim': hidden_dim
                }, best_model_path)
        
        logger.info(f"\n✓ Training complete. Best model saved to {best_model_path}")
        logger.info(f"Best loss: {best_loss:.4f}")
        
        # Evaluate on test set
        self.evaluate_model(model, test_graphs, test_labels_list)
        
        return str(best_model_path)
    
    def _ensure_consistent_node_types(self, graphs: List[HeteroData]) -> List[HeteroData]:
        """Simplified: Keep alert nodes and create minimal edges if needed."""
        import torch
        
        simplified_graphs = []
        for graph in graphs:
            # Check if alert node type exists
            if 'alert' not in graph.node_types:
                continue
                
            num_alerts = graph['alert'].x.shape[0]
            
            # Create minimal graph with only alert nodes
            new_graph = HeteroData()
            new_graph['alert'].x = graph['alert'].x
            
            # Copy alert-to-alert edges if they exist
            has_edges = False
            for edge_type in graph.edge_types:
                src, rel, dst = edge_type
                if src == 'alert' and dst == 'alert':
                    edge_index = graph[edge_type].edge_index
                    if edge_index.numel() > 0 and edge_index.max() < num_alerts:
                        new_graph[edge_type].edge_index = edge_index
                        has_edges = True
            
            # If no alert-to-alert edges, create self-loops so GNN can work
            if not has_edges:
                # Create self-loop edges for each alert
                self_loops = torch.arange(num_alerts, dtype=torch.long).unsqueeze(0).repeat(2, 1)
                new_graph[('alert', 'self_loop', 'alert')].edge_index = self_loops
            
            simplified_graphs.append(new_graph)
        
        logger.info(f"Simplified {len(simplified_graphs)} graphs to alert-only")
        return simplified_graphs
    
    def evaluate_model(self, model, test_graphs, test_labels):
        """Evaluate trained model on test set."""
        logger.info(f"\n{'='*60}")
        logger.info("Evaluation on Test Set")
        logger.info(f"{'='*60}")
        
        model.eval()
        correct = 0
        total = 0
        
        with torch.no_grad():
            for graph, true_label in zip(test_graphs, test_labels):
                graph = graph.to(self.device)
                cluster_logits, _ = model(graph)
                
                # Majority vote prediction
                predictions = torch.argmax(cluster_logits, dim=-1)
                pred_label = torch.mode(predictions).values.item()
                
                if pred_label == true_label:
                    correct += 1
                total += 1
        
        accuracy = correct / total if total > 0 else 0
        logger.info(f"Test Accuracy: {accuracy:.4f} ({correct}/{total})")
        
        return accuracy
    
    def train_all_datasets(self):
        """Train on all available datasets."""
        available_datasets = []
        
        # Check for available datasets
        for dataset_name in ['nsl_kdd', 'unsw_nb15', 'cicids2017', 'cicids2018']:
            filepath = self.dataset_path / dataset_name / "mitre_format.csv"
            if filepath.exists():
                available_datasets.append(dataset_name)
        
        if not available_datasets:
            logger.error("No datasets found. Run download_datasets.py first.")
            return
        
        logger.info(f"Found datasets: {available_datasets}")
        
        trained_models = {}
        
        for dataset_name in available_datasets:
            model_path = self.train_on_dataset(dataset_name)
            if model_path:
                trained_models[dataset_name] = model_path
        
        logger.info(f"\n{'='*60}")
        logger.info("Training Summary")
        logger.info(f"{'='*60}")
        for dataset, path in trained_models.items():
            logger.info(f"✓ {dataset}: {path}")
        
        return trained_models


def main():
    """Main training entry point."""
    trainer = DatasetTrainer()
    trained_models = trainer.train_all_datasets()
    
    if trained_models:
        logger.info(f"\n{'='*60}")
        logger.info("All models trained successfully!")
        logger.info(f"Models saved to: {trainer.output_path}")
        logger.info(f"{'='*60}")
    else:
        logger.error("Training failed. Check dataset availability.")


if __name__ == "__main__":
    main()
