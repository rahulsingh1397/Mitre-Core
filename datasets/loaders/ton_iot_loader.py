import pandas as pd
import numpy as np
from pathlib import Path

class TONIoTLoader:
    def __init__(self):
        pass
        
    def load_and_preprocess(self, file_path):
        if file_path.endswith('.parquet'):
            df = pd.read_parquet(file_path)
        else:
            df = pd.read_csv(file_path)
            
        if 'MalwareIntelAttackType' not in df.columns:
            if 'type' in df.columns:
                df['MalwareIntelAttackType'] = df['type']
            elif 'Attack_Type' in df.columns:
                df['MalwareIntelAttackType'] = df['Attack_Type']
            else:
                df['MalwareIntelAttackType'] = 'Normal'
                
        for col in ['AlertId', 'SourceAddress', 'DestinationAddress', 'DeviceAddress', 'SourceUserName', 'SourceHostName', 'DeviceHostName', 'DestinationHostName', 'AttackSeverity', 'EndDate']:
            if col not in df.columns:
                if col == 'EndDate':
                    df[col] = pd.Timestamp('2026-01-01').value // 10**9 + df.index * 60
                elif col == 'AttackSeverity':
                    df[col] = 10
                elif col == 'AlertId':
                    df[col] = 'TON_' + df.index.astype(str)
                else:
                    df[col] = col + '_val'
                    
        return df[['AlertId', 'SourceAddress', 'DestinationAddress', 'DeviceAddress', 'SourceUserName', 'SourceHostName', 'DeviceHostName', 'DestinationHostName', 'MalwareIntelAttackType', 'AttackSeverity', 'EndDate']]

    def stratified_sample(self, file_path, n=500, seed=42):
        df = self.load_and_preprocess(file_path)
        np.random.seed(seed)
        
        counts = df['MalwareIntelAttackType'].value_counts()
        props = counts / len(df)
        
        samples = []
        for attack_type, prop in props.items():
            n_samples = max(1, int(np.round(prop * n)))
            subset = df[df['MalwareIntelAttackType'] == attack_type]
            if len(subset) > 0:
                n_samples = min(n_samples, len(subset))
                samples.append(subset.sample(n=n_samples, random_state=seed))
                
        sampled_df = pd.concat(samples)
        
        if len(sampled_df) > n:
            sampled_df = sampled_df.sample(n=n, random_state=seed)
        elif len(sampled_df) < n:
            remaining = n - len(sampled_df)
            available = df[~df.index.isin(sampled_df.index)]
            if len(available) > 0:
                sampled_df = pd.concat([sampled_df, available.sample(n=min(remaining, len(available)), random_state=seed)])
                
        return sampled_df

if __name__ == '__main__':
    loader = TONIoTLoader()
    import os
    if os.path.exists('datasets/TON_IoT/mitre_format.parquet'):
        df = loader.stratified_sample('datasets/TON_IoT/mitre_format.parquet', n=500)
        print('Stratified sample shape:', df.shape)
        print(df['MalwareIntelAttackType'].value_counts())
