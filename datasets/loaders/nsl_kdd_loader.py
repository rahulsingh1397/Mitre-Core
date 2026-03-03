import pandas as pd
import numpy as np
import os

class NSLKDDLoader:
    def __init__(self):
        self.columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level']
        
    def load_and_preprocess(self, file_path):
        df = pd.read_csv(file_path, header=None)
        if len(df.columns) == 43:
            df.columns = self.columns
        elif len(df.columns) == 42:
            df.columns = self.columns[:-1]
        
        df['SourceAddress'] = '192.168.1.' + (df['src_bytes'] % 254 + 1).astype(str)
        df['DestinationAddress'] = '10.0.0.' + (df['dst_bytes'] % 254 + 1).astype(str)
        protocol_map = {'tcp': '172.16.0.1', 'udp': '172.16.0.2', 'icmp': '172.16.0.3'}
        df['DeviceAddress'] = df['protocol_type'].map(protocol_map).fillna('172.16.0.4')
        
        df['SourceUserName'] = 'user_' + (df.index % 100).astype(str)
        df['SourceHostName'] = df['service'].astype(str) + '_host'
        df['DeviceHostName'] = 'fw_' + df['flag'].astype(str)
        df['DestinationHostName'] = 'target_' + (df['dst_host_count'] % 50).astype(str)
        
        df['MalwareIntelAttackType'] = df['label']
        if 'difficulty_level' in df.columns:
            df['AttackSeverity'] = df['difficulty_level']
        else:
            df['AttackSeverity'] = 10
            
        df['EndDate'] = pd.Timestamp('2026-01-01').value // 10**9 + df.index * 60 + df['duration']
        df['AlertId'] = 'NSL_' + df.index.astype(str)
        
        return df[['AlertId', 'SourceAddress', 'DestinationAddress', 'DeviceAddress', 'SourceUserName', 'SourceHostName', 'DeviceHostName', 'DestinationHostName', 'MalwareIntelAttackType', 'AttackSeverity', 'EndDate']]

if __name__ == '__main__':
    loader = NSLKDDLoader()
    if os.path.exists('datasets/nsl_kdd/KDDTrain+.txt'):
        df = loader.load_and_preprocess('datasets/nsl_kdd/KDDTrain+.txt')
        print('Shape:', df.shape)
        print(df.head(3))
