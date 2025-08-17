import sys
import re

def convert_trace(input_file, output_file):
    pattern = re.compile(r"core\s+\d+:\s+(0x[0-9a-fA-F]+)\s+\(0x[0-9a-fA-F]+\)\s+(.+)")
    with open(input_file, "r") as infile, open(output_file, "w") as outfile:
        for line in infile:
            line = line.strip()
            if not line or line.startswith("Created trace_encoder") or line.startswith(">>>>"):
                continue
            match = pattern.match(line)
            if match:
                addr, instr = match.groups()
                outfile.write(f"{addr}: {instr.strip()}\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_trace.txt> <output_trace.txt>")
        sys.exit(1)

    convert_trace(sys.argv[1], sys.argv[2])