import pandas as pd
import sys

# usage: python clean_csv.py input.csv output.csv
input_file = sys.argv[1]
output_file = sys.argv[2]

# columns to drop
cols_to_drop = [
    "context", "ienable", "encoder_mode", "irreport", "irdepth",
    "ioptions", "qual_status", "denable", "dloss", "doptions"
]

# load, drop, save
df = pd.read_csv(input_file)
df = df.drop(columns=[c for c in cols_to_drop if c in df.columns])
df.to_csv(output_file, index=False)

print(f"Saved cleaned CSV as {output_file}")