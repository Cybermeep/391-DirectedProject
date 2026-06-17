"""
Test script for data loader.
"""
import sys
sys.path.insert(0, 'src')

from ml_pipeline.data_loader import DataLoader
from pathlib import Path

print("=" * 60)
print("Testing Data Loader")
print("=" * 60)

data_loader = DataLoader(
    data_path='./data/datasets/CSE-CIC-IDS2018',
    selected_attacks=['DoS', 'DDoS', 'Bruteforce', 'PortScan', 'Botnet']
)

# Load just 100 rows
print("\nLoading 100 rows...")
df = data_loader.load_dataset(subset_size=100)
print(f'Loaded {len(df)} rows')
print(f'Columns: {len(df.columns)}')

# Prepare data
print("\nPreparing data...")
df_prepared = data_loader.prepare_data(df, balance=False)
print('Data preparation successful!')
print(f'Label distribution: {df_prepared["Label_Binary"].value_counts().to_dict()}')
print(f'Features: {len(df_prepared.columns) - 1} feature columns')

print("\n" + "=" * 60)
print("Test complete!")
print("=" * 60)