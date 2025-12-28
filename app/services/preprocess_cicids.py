"""
CICIDS2017 Complete Preprocessing Script
=========================================

This script preprocesses Monday (training), Friday DDoS, and Friday PortScan files:
1. Handles missing values
2. Removes invalid rows
3. Standardizes column names
4. Ensures all required columns exist
5. Saves clean versions ready for cicids_loader.py

Files to preprocess:
- Monday-WorkingHours.pcap_ISCX (Normal traffic - for training)
- Friday-WorkingHours-Afternoon-DDos.pcap_ISCX (DDoS attacks - for testing)
- Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX (Port scan attacks - for testing)

Usage:
    python preprocess_cicids.py
"""

import pandas as pd
import numpy as np
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')


class CICIDS2017Preprocessor:
    """Preprocess CICIDS2017 dataset files"""
    
    # Required columns for Kitsune - Essential features for network intrusion detection
    REQUIRED_COLUMNS = [
        # Network identifiers (5-tuple)
        'Source IP',
        'Destination IP',
        'Source Port',
        'Destination Port',
        'Protocol',
        
        # Timestamp (CRITICAL for temporal features)
        'Timestamp',
        
        # Flow characteristics
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Total Length of Fwd Packets',
        'Total Length of Bwd Packets',
        
        # Packet size statistics (for anomaly detection)
        'Fwd Packet Length Max',
        'Fwd Packet Length Min',
        'Fwd Packet Length Mean',
        'Fwd Packet Length Std',
        'Bwd Packet Length Max',
        'Bwd Packet Length Min',
        'Bwd Packet Length Mean',
        'Bwd Packet Length Std',
        
        # Rate features (CRITICAL for DDoS detection)
        'Flow Bytes/s',
        'Flow Packets/s',
        'Fwd Packets/s',
        'Bwd Packets/s',
        
        # Inter-arrival time (CRITICAL for timing attacks and jitter)
        'Flow IAT Mean',
        'Flow IAT Std',
        'Flow IAT Max',
        'Flow IAT Min',
        'Fwd IAT Mean',
        'Fwd IAT Std',
        'Fwd IAT Max',
        'Fwd IAT Min',
        'Bwd IAT Mean',
        'Bwd IAT Std',
        'Bwd IAT Max',
        'Bwd IAT Min',
        
        # TCP Flags (CRITICAL for port scan and connection anomalies)
        'FIN Flag Count',
        'SYN Flag Count',
        'RST Flag Count',
        'PSH Flag Count',
        'ACK Flag Count',
        'URG Flag Count',
        
        # Header and packet statistics
        'Fwd Header Length',
        'Bwd Header Length',
        'Min Packet Length',
        'Max Packet Length',
        'Packet Length Mean',
        'Packet Length Std',
        
        # Active/Idle time (for session behavior)
        'Active Mean',
        'Active Std',
        'Active Max',
        'Active Min',
        'Idle Mean',
        'Idle Std',
        'Idle Max',
        'Idle Min',
        
        # Label (for validation)
        'Label'
    ]
    
    # Columns to standardize names (handle spacing issues in CICIDS2017)
    COLUMN_NAME_MAP = {
        # Remove leading spaces from column names
        ' Source IP': 'Source IP',
        ' Destination IP': 'Destination IP',
        ' Source Port': 'Source Port',
        ' Destination Port': 'Destination Port',
        ' Protocol': 'Protocol',
        ' Timestamp': 'Timestamp',
        ' Flow Duration': 'Flow Duration',
        ' Total Fwd Packets': 'Total Fwd Packets',
        ' Total Backward Packets': 'Total Backward Packets',
        'Total Length of Fwd Packets': 'Total Length of Fwd Packets',
        ' Total Length of Bwd Packets': 'Total Length of Bwd Packets',
        ' Fwd Packet Length Max': 'Fwd Packet Length Max',
        ' Fwd Packet Length Min': 'Fwd Packet Length Min',
        ' Fwd Packet Length Mean': 'Fwd Packet Length Mean',
        ' Fwd Packet Length Std': 'Fwd Packet Length Std',
        'Bwd Packet Length Max': 'Bwd Packet Length Max',
        ' Bwd Packet Length Min': 'Bwd Packet Length Min',
        ' Bwd Packet Length Mean': 'Bwd Packet Length Mean',
        ' Bwd Packet Length Std': 'Bwd Packet Length Std',
        'Flow Bytes/s': 'Flow Bytes/s',
        ' Flow Packets/s': 'Flow Packets/s',
        ' Flow IAT Mean': 'Flow IAT Mean',
        ' Flow IAT Std': 'Flow IAT Std',
        ' Flow IAT Max': 'Flow IAT Max',
        ' Flow IAT Min': 'Flow IAT Min',
        'Fwd IAT Total': 'Fwd IAT Total',
        ' Fwd IAT Mean': 'Fwd IAT Mean',
        ' Fwd IAT Std': 'Fwd IAT Std',
        ' Fwd IAT Max': 'Fwd IAT Max',
        ' Fwd IAT Min': 'Fwd IAT Min',
        'Bwd IAT Total': 'Bwd IAT Total',
        ' Bwd IAT Mean': 'Bwd IAT Mean',
        ' Bwd IAT Std': 'Bwd IAT Std',
        ' Bwd IAT Max': 'Bwd IAT Max',
        ' Bwd IAT Min': 'Bwd IAT Min',
        'FIN Flag Count': 'FIN Flag Count',
        ' SYN Flag Count': 'SYN Flag Count',
        ' RST Flag Count': 'RST Flag Count',
        ' PSH Flag Count': 'PSH Flag Count',
        ' ACK Flag Count': 'ACK Flag Count',
        ' URG Flag Count': 'URG Flag Count',
        ' Fwd Header Length': 'Fwd Header Length',
        ' Bwd Header Length': 'Bwd Header Length',
        'Fwd Packets/s': 'Fwd Packets/s',
        ' Bwd Packets/s': 'Bwd Packets/s',
        ' Min Packet Length': 'Min Packet Length',
        ' Max Packet Length': 'Max Packet Length',
        ' Packet Length Mean': 'Packet Length Mean',
        ' Packet Length Std': 'Packet Length Std',
        'Active Mean': 'Active Mean',
        ' Active Std': 'Active Std',
        ' Active Max': 'Active Max',
        ' Active Min': 'Active Min',
        'Idle Mean': 'Idle Mean',
        ' Idle Std': 'Idle Std',
        ' Idle Max': 'Idle Max',
        ' Idle Min': 'Idle Min',
        ' Label': 'Label',
        'Label': 'Label'
    }
    
    def __init__(self, input_dir='datasets/CICIDS2017', output_dir='datasets/CICIDS2017/preprocessed'):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        print("="*70)
        print("CICIDS2017 PREPROCESSOR")
        print("="*70)
        print(f"Input directory:  {self.input_dir}")
        print(f"Output directory: {self.output_dir}")
        print("="*70)
    
    def load_csv(self, filename: str) -> pd.DataFrame:
        """Load CSV file with error handling"""
        filepath = self.input_dir / filename
        
        print(f"\nLoading: {filename}")
        print(f"   Path: {filepath}")
        
        if not filepath.exists():
            print(f"File not found!")
            return None
        
        try:
            # Try reading with different encodings
            try:
                df = pd.read_csv(filepath, encoding='utf-8')
            except UnicodeDecodeError:
                df = pd.read_csv(filepath, encoding='latin-1')
            
            print(f"Loaded successfully")
            print(f"   Rows: {len(df):,}")
            print(f"   Columns: {len(df.columns)}")
            
            return df
            
        except Exception as e:
            print(f"Error loading file: {e}")
            return None
    
    def standardize_column_names(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize column names (remove leading/trailing spaces)"""
        print(f"\nStandardizing column names...")
        
        # Strip whitespace from all column names
        df.columns = df.columns.str.strip()
        
        # Apply specific mappings if needed
        df = df.rename(columns=self.COLUMN_NAME_MAP)
        
        print(f"Columns standardized")
        return df
    
    def check_required_columns(self, df: pd.DataFrame, filename: str) -> bool:
        """Check if all required columns exist"""
        print(f"\nChecking required columns for {filename}...")
        
        missing_columns = []
        for col in self.REQUIRED_COLUMNS:
            if col not in df.columns:
                missing_columns.append(col)
        
        if missing_columns:
            print(f"Missing columns: {missing_columns}")
            print(f"\n   Available columns:")
            for col in sorted(df.columns):
                print(f"      - {col}")
            return False
        else:
            print(f"All required columns present")
            return True
    
    def handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values in the dataset"""
        print(f"\nChecking for missing values...")
        
        initial_rows = len(df)
        
        # Check missing values in required columns
        missing_counts = {}
        for col in self.REQUIRED_COLUMNS:
            if col in df.columns:
                missing = df[col].isna().sum()
                if missing > 0:
                    missing_counts[col] = missing
        
        if missing_counts:
            print(f"Found missing values:")
            for col, count in missing_counts.items():
                percentage = (count / initial_rows) * 100
                print(f"      {col}: {count} ({percentage:.2f}%)")
            
            # Drop rows with missing values in critical columns
            df = df.dropna(subset=self.REQUIRED_COLUMNS)
            removed = initial_rows - len(df)
            print(f"Removed {removed} rows with missing values")
        else:
            print(f"No missing values in required columns")
        
        return df
    
    def handle_infinite_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replace infinite values with reasonable defaults"""
        print(f"\nChecking for infinite values...")
        
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        # Replace inf/-inf with NaN, then fill with 0
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        
        inf_counts = df[numeric_cols].isna().sum()
        total_inf = inf_counts.sum()
        
        if total_inf > 0:
            print(f"Found {total_inf} infinite values")
            df[numeric_cols] = df[numeric_cols].fillna(0)
            print(f"Replaced with 0")
        else:
            print(f"No infinite values found")
        
        return df
    
    def validate_data_types(self, df: pd.DataFrame) -> pd.DataFrame:
        """Ensure correct data types for columns"""
        print(f"\nValidating data types...")
        
        # Ensure ports are integers
        for col in ['Source Port', 'Destination Port']:
            if col in df.columns:
                try:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
                except:
                    pass
        
        # Ensure protocol is integer
        if 'Protocol' in df.columns:
            try:
                df['Protocol'] = pd.to_numeric(df['Protocol'], errors='coerce').fillna(6).astype(int)
            except:
                pass
        
        # Ensure packet length is numeric
        if 'Total Length of Fwd Packets' in df.columns:
            try:
                df['Total Length of Fwd Packets'] = pd.to_numeric(
                    df['Total Length of Fwd Packets'], 
                    errors='coerce'
                ).fillna(0)
            except:
                pass
        
        print(f"Data types validated")
        return df
    
    def remove_invalid_ips(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove rows with invalid IP addresses"""
        print(f"\nChecking IP addresses...")
        
        initial_rows = len(df)
        
        # Remove rows with 0.0.0.0 or invalid IPs
        if 'Source IP' in df.columns:
            df = df[df['Source IP'] != '0.0.0.0']
            df = df[df['Source IP'].notna()]
        
        if 'Destination IP' in df.columns:
            df = df[df['Destination IP'] != '0.0.0.0']
            df = df[df['Destination IP'].notna()]
        
        removed = initial_rows - len(df)
        if removed > 0:
            print(f"Removed {removed} rows with invalid IPs")
        else:
            print(f"All IPs valid")
        
        return df
    
    def keep_only_required_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Keep only the required columns and remove all others"""
        print(f"\nFiltering columns...")
        print(f"   Before: {len(df.columns)} columns")
        
        # Keep only required columns
        df = df[self.REQUIRED_COLUMNS]
        
        print(f"   After: {len(df.columns)} columns")
        print(f"   Kept columns: {list(df.columns)}")
        
        return df
    
    def show_label_distribution(self, df: pd.DataFrame, filename: str):
        """Show distribution of labels"""
        print(f"\nLabel distribution for {filename}:")
        
        if 'Label' not in df.columns:
            print(f"No 'Label' column found")
            return
        
        label_counts = df['Label'].value_counts()
        total = len(df)
        
        for label, count in label_counts.items():
            percentage = (count / total) * 100
            print(f"   {label:15s}: {count:8,} ({percentage:5.2f}%)")
    
    def save_preprocessed(self, df: pd.DataFrame, original_filename: str) -> str:
        """Save preprocessed dataframe"""
        # Generate output filename
        output_filename = original_filename.replace('.csv', '_preprocessed.csv')
        if not output_filename.endswith('.csv'):
            output_filename += '_preprocessed.csv'
        
        output_path = self.output_dir / output_filename
        
        print(f"\nSaving preprocessed file...")
        print(f"   Output: {output_path}")
        
        try:
            df.to_csv(output_path, index=False)
            file_size = output_path.stat().st_size / (1024 * 1024)  # MB
            print(f"Saved successfully ({file_size:.2f} MB)")
            print(f"   Final rows: {len(df):,}")
            return str(output_path)
        except Exception as e:
            print(f"Error saving file: {e}")
            return None
    
    def preprocess_file(self, filename: str) -> str:
        """Complete preprocessing pipeline for a single file"""
        print(f"\n{'='*70}")
        print(f"PROCESSING: {filename}")
        print(f"{'='*70}")
        
        # Load file
        df = self.load_csv(filename)
        if df is None:
            return None
        
        # Show initial state
        print(f"\nInitial state:")
        print(f"   Rows: {len(df):,}")
        print(f"   Columns: {len(df.columns)}")
        
        # Preprocessing steps
        df = self.standardize_column_names(df)
        
        if not self.check_required_columns(df, filename):
            print(f"Cannot proceed - missing required columns")
            return None
        
        df = self.handle_missing_values(df)
        df = self.handle_infinite_values(df)
        df = self.validate_data_types(df)
        df = self.remove_invalid_ips(df)
        df = self.keep_only_required_columns(df)
        
        # Show label distribution
        self.show_label_distribution(df, filename)
        
        # Save preprocessed file
        output_path = self.save_preprocessed(df, filename)
        
        print(f"\n{'='*70}")
        print(f"COMPLETED: {filename}")
        print(f"{'='*70}")
        
        return output_path
    
    def preprocess_all(self):
        """Preprocess Monday, Friday DDoS, and Friday PortScan files"""
        print(f"\n{'#'*70}")
        print(f"PREPROCESSING ALL CICIDS2017 FILES")
        print(f"{'#'*70}\n")
        
        files_to_process = [
            'Monday-WorkingHours.pcap_ISCX.csv',
            'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
            'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
        ]
        
        results = {}
        
        for filename in files_to_process:
            output_path = self.preprocess_file(filename)
            results[filename] = output_path
        
        # Final summary
        print(f"\n{'#'*70}")
        print(f"PREPROCESSING COMPLETE - SUMMARY")
        print(f"{'#'*70}\n")
        
        for original, preprocessed in results.items():
            status = "✓ Success" if preprocessed else "✗ Failed"
            print(f"{status}: {original}")
            if preprocessed:
                print(f"         -> {preprocessed}")
        
        print(f"\n{'#'*70}")
        print(f"READY FOR KITSUNE!")
        print(f"{'#'*70}\n")
        
        print("Next steps:")
        print("1. Use preprocessed files in cicids_loader.py:")
        print(f"   - Training:      {self.output_dir}/Monday-WorkingHours.pcap_ISCX_preprocessed.csv")
        print(f"   - DDoS Testing:  {self.output_dir}/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_preprocessed.csv")
        print(f"   - PortScan Test: {self.output_dir}/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX_preprocessed.csv")
        print()
        print("2. Run training:")
        print("   python cicids_loader.py --mode train --file datasets/CICIDS2017/preprocessed/Monday-WorkingHours.pcap_ISCX_preprocessed.csv")
        print()
        print("3. Run DDoS detection:")
        print("   python cicids_loader.py --mode detect --file datasets/CICIDS2017/preprocessed/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_preprocessed.csv")
        print()
        print("4. Run PortScan detection:")
        print("   python cicids_loader.py --mode detect --file datasets/CICIDS2017/preprocessed/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX_preprocessed.csv")
        print()


def main():
    """Main function"""
    import sys
    
    # Check if custom paths provided
    if len(sys.argv) > 1:
        input_dir = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else None
        
        if output_dir:
            preprocessor = CICIDS2017Preprocessor(input_dir=input_dir, output_dir=output_dir)
        else:
            preprocessor = CICIDS2017Preprocessor(input_dir=input_dir)
    else:
        # Default paths - look in current directory
        preprocessor = CICIDS2017Preprocessor()
    
    # Preprocess all files
    preprocessor.preprocess_all()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nPreprocessing interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()