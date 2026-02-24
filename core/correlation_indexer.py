from collections import defaultdict
import random
import time
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
# Optional testing/plotting imports are moved under __main__


# Legacy function - replaced by calculate_adaptive_threshold
def adaptive_correlation_threshold(cluster_size: int, data_variance: float) -> float:
    """DEPRECATED: Use calculate_adaptive_threshold instead"""
    return 0.3


def weighted_correlation_score(addresses_common: set, usernames_common: set, 
                             temporal_proximity: float = 0) -> float:
    """Enhanced scoring with configurable weights"""
    address_weight = 0.6
    username_weight = 0.3
    temporal_weight = 0.1
    
    score = (len(addresses_common) * address_weight + 
             len(usernames_common) * username_weight +
             temporal_proximity * temporal_weight)
    return score


def calculate_temporal_proximity(timestamp1: str, timestamp2: str) -> float:
    """Calculate temporal proximity score between two events"""
    try:
        from datetime import datetime
        t1 = pd.to_datetime(timestamp1)
        t2 = pd.to_datetime(timestamp2)
        time_diff = abs((t1 - t2).total_seconds())
        
        # Normalize to 0-1 scale (events within 1 hour get max score)
        max_time_window = 3600  # 1 hour in seconds
        proximity = max(0, 1 - (time_diff / max_time_window))
        return proximity
    except Exception:
        return 0.0


def enhanced_correlation(data: pd.DataFrame, usernames: List[str], addresses: List[str], 
                        use_temporal: bool = False, use_adaptive_threshold: bool = True,
                        threshold_override: Optional[float] = None) -> pd.DataFrame:
    """
    Enhanced correlation function using Union-Find algorithm for proper clustering
    
    Args:
        data: DataFrame with security events
        usernames: List of username column names
        addresses: List of address column names  
        use_temporal: Whether to include temporal proximity in scoring
        use_adaptive_threshold: Whether to use adaptive threshold calculation
        
    Returns:
        DataFrame with predicted clusters and correlation metadata
    """
    
    if data.empty:
        raise ValueError("Input data cannot be empty")
    
    if not all(col in data.columns for col in addresses + usernames):
        missing_cols = [col for col in addresses + usernames if col not in data.columns]
        raise ValueError(f"Missing required columns: {missing_cols}")
    
    n_events = len(data)
    
    # Calculate adaptive threshold with theoretical justification
    if threshold_override is not None:
        threshold = threshold_override
    elif use_adaptive_threshold:
        threshold = calculate_adaptive_threshold(data, addresses, usernames)
    else:
        threshold = 0.3  # Default threshold from literature (Valeur et al., 2004)
    
    # Initialize Union-Find structure for proper clustering
    parent = list(range(n_events))
    rank = [0] * n_events
    
    def find(x):
        """Find root of element x with path compression"""
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]
    
    def union(x, y):
        """Union two sets by rank"""
        root_x, root_y = find(x), find(y)
        if root_x != root_y:
            if rank[root_x] < rank[root_y]:
                parent[root_x] = root_y
            elif rank[root_x] > rank[root_y]:
                parent[root_y] = root_x
            else:
                parent[root_y] = root_x
                rank[root_x] += 1
    
    # Calculate pairwise correlation scores
    correlation_matrix = np.zeros((n_events, n_events))
    
    for i in range(n_events):
        for j in range(i + 1, n_events):
            row_i = data.iloc[i]
            row_j = data.iloc[j]
            
            # Calculate feature similarity
            common_addresses = calculate_feature_similarity(row_i, row_j, addresses)
            common_usernames = calculate_feature_similarity(row_i, row_j, usernames)
            
            # Calculate temporal proximity if available
            temporal_score = 0.0
            if use_temporal and 'EndDate' in data.columns:
                temporal_score = calculate_temporal_proximity(
                    str(row_i['EndDate']), str(row_j['EndDate'])
                )
            
            # Compute weighted correlation score
            corr_score = weighted_correlation_score(
                common_addresses, common_usernames, temporal_score
            )
            
            correlation_matrix[i][j] = corr_score
            correlation_matrix[j][i] = corr_score
            
            # Union events if correlation exceeds threshold
            if corr_score >= threshold:
                union(i, j)
    
    # Extract final cluster assignments
    clusters = [find(i) for i in range(n_events)]
    
    # Renumber clusters to be consecutive starting from 0
    unique_clusters = sorted(set(clusters))
    cluster_mapping = {old_id: new_id for new_id, old_id in enumerate(unique_clusters)}
    final_clusters = [cluster_mapping[cluster_id] for cluster_id in clusters]
    
    # Add results to dataframe
    result_data = data.copy()
    result_data['pred_cluster'] = final_clusters
    result_data['correlation_threshold_used'] = threshold
    result_data['max_correlation_score'] = [max(correlation_matrix[i]) for i in range(n_events)]
    
    return result_data


def calculate_adaptive_threshold(data: pd.DataFrame, addresses: List[str], 
                               usernames: List[str]) -> float:
    """
    Calculate adaptive threshold based on data characteristics and theoretical principles
    
    Based on:
    1. Dataset size (larger datasets need higher thresholds to avoid over-clustering)
    2. Feature diversity (more diverse data needs lower thresholds)
    3. Temporal spread (longer time spans suggest lower correlation requirements)
    
    Args:
        data: Input DataFrame
        addresses: Address column names
        usernames: Username column names
        
    Returns:
        Adaptive threshold value
    """
    
    base_threshold = 0.3  # From alert correlation literature
    
    # Size factor: larger datasets need slightly higher thresholds
    size_factor = min(0.1, np.log10(len(data)) / 10)
    
    # Diversity factor: calculate feature entropy
    diversity_factor = 0.0
    for col in addresses + usernames:
        if col in data.columns:
            unique_ratio = len(data[col].dropna().unique()) / len(data)
            diversity_factor += unique_ratio
    
    diversity_factor = diversity_factor / len(addresses + usernames)
    diversity_adjustment = (diversity_factor - 0.5) * 0.2  # Normalize around 0.5
    
    # Temporal factor: if timestamps available, consider time spread
    temporal_factor = 0.0
    if 'EndDate' in data.columns:
        try:
            timestamps = pd.to_datetime(data['EndDate'], errors='coerce').dropna()
            if len(timestamps) > 1:
                time_span_hours = (timestamps.max() - timestamps.min()).total_seconds() / 3600
                # Longer time spans suggest need for lower thresholds (more lenient correlation)
                temporal_factor = -min(0.1, time_span_hours / 1000)  # Normalize to reasonable range
        except Exception:
            temporal_factor = 0.0
    
    adaptive_threshold = base_threshold + size_factor + diversity_adjustment + temporal_factor
    
    # Ensure threshold stays in reasonable bounds
    return max(0.1, min(0.8, adaptive_threshold))


def calculate_feature_similarity(row1: pd.Series, row2: pd.Series, 
                               feature_columns: List[str]) -> set:
    """
    Calculate common features between two events, handling missing values properly
    
    Args:
        row1, row2: Event data rows
        feature_columns: Columns to compare
        
    Returns:
        Set of common non-null feature values
    """
    
    common_features = set()
    
    for col in feature_columns:
        val1 = str(row1[col]) if pd.notna(row1[col]) else None
        val2 = str(row2[col]) if pd.notna(row2[col]) else None
        
        # Only consider as common if both values are non-null and equal
        if (val1 is not None and val2 is not None and 
            val1 not in ['nan', 'NIL', 'UNKNOWN', ''] and
            val2 not in ['nan', 'NIL', 'UNKNOWN', ''] and
            val1 == val2):
            common_features.add(val1)
    
    return common_features


def correlation(data, usernames, addresses):
    """Legacy correlation function - kept for backward compatibility"""
    return enhanced_correlation(data, usernames, addresses, 
                              use_temporal=False, use_adaptive_threshold=False)
       

def main(uri = 'Data/Raw_data/test_dataset.csv'):
    """Main function for testing correlation algorithm"""
    try:
        # Optional imports to avoid hard dependencies during library use
        try:
            import Testing  # noqa: F401
        except Exception as e:
            print(f"Warning: optional Testing module unavailable: {e}")
            Testing = None  # type: ignore
        try:
            import plots  # noqa: F401
        except Exception as e:
            print(f"Warning: optional plots module unavailable: {e}")
            plots = None  # type: ignore

        from pathlib import Path
        file_name = Path(uri).name
        if Testing:
            df = Testing.build_data(10)
        else:
            # Minimal fallback synthetic data for ad-hoc testing
            df = pd.DataFrame({
                'SourceAddress': ['10.0.0.1', '10.0.0.2', '10.0.0.1'],
                'DestinationAddress': ['192.168.1.5', '192.168.1.6', '192.168.1.5'],
                'DeviceAddress': ['172.16.0.10', '172.16.0.10', '172.16.0.10'],
                'SourceHostName': ['hostA', 'hostB', 'hostA'],
                'DeviceHostName': ['fw1', 'fw1', 'fw1'],
                'DestinationHostName': ['srv1', 'srv2', 'srv1'],
                'EndDate': ['2023-01-01T10:00:00', '2023-01-01T10:05:00', '2023-01-01T10:10:00']
            })
        addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
        usernames = ["SourceHostName","DeviceHostName","DestinationHostName"]

        df = df.drop_duplicates(keep="first", ignore_index=True)
        res = enhanced_correlation(df, usernames, addresses, 
                                 use_temporal=True, use_adaptive_threshold=True)
        
        path = str(Path('Data/Cleaned') / f'Test_{file_name}')
        res.to_csv(path, index=False)   
        
        print(f"Correlation completed: {len(set(res['pred_cluster']))} clusters found")
        print(f"Threshold used: {res['correlation_threshold_used'].iloc[0]:.3f}")
        
        # Optional: generate plots if needed
        # plots.main(uri=path, addresses=addresses, usernames=usernames)   
        
    except Exception as e:
        print(f"Error in main function: {e}")


if __name__ == "__main__":
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("Enhanced correlation testing started at: " + str(current_time))

    main()

    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("Enhanced correlation testing ended at: " + str(current_time))
         
      