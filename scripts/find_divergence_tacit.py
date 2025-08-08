# Parse the spike trace and the decoder dump to find any divergence
import argparse
import re

def clean_line(line):
    # Remove everything in square brackets and strip
    line = re.sub(r'\[.*?\]', '', line)
    return line.strip()

def read_reference_file(reference_file):
    """
    Reads the reference file and returns a list of (address, instruction) tuples.
    """
    reference = []
    with open(reference_file, 'r') as f:
        for line in f:
            line = clean_line(line)
            if line and ':' in line and not line.lower().startswith('timestamp'):
                address, instr = line.split(':', 1)
                reference.append((address.strip().lower(), instr.strip()))
    return reference

def read_created_file(created_file):
    """
    Reads the created file and returns a list of (address, instruction) tuples, skipping the first instruction.
    """
    created = []
    with open(created_file, 'r') as f:
        for line in f:
            line = clean_line(line)
            if line and ':' in line and not line.lower().startswith('timestamp'):
                address, instr = line.split(':', 1)
                created.append((address.strip().lower(), instr.strip()))
    # Skip the first instruction
    return created[1:]

def find_first_divergence(reference, created):
    """
    Finds the first divergence between the reference and created traces.
    Returns the matching segment and the first pair of lines that diverge.
    """
    count = 0
    for ref, crt in zip(reference, created):
        if ref != crt:
            print(f"Divergence at line {count+1}:")
            print(f"  Reference: {ref[0]}: {ref[1]}")
            print(f"  Created  : {crt[0]}: {crt[1]}")
            return count, ref, crt
        count += 1

    min_len = min(len(reference), len(created))
    if len(reference) < len(created):
        print(f"No divergence found. Reference file is shorter with {len(reference)} lines.")
    elif len(created) < len(reference):
        print(f"No divergence found. Created file is shorter with {len(created)} lines.")
    else:
        print("No divergence found. Files match and are of the same length.")
    return count, None, None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Find divergence in trace.")
    parser.add_argument("-r", "--ref_file", type=str, required=True, help="Path to the reference trace file.")
    parser.add_argument("-d", "--decoder_dump", type=str, required=True, help="Path to the decoder dump file.")
    args = parser.parse_args()

    reference = read_reference_file(args.ref_file)
    created = read_created_file(args.decoder_dump)

    count, ref, crt = find_first_divergence(reference, created)

    if ref and crt:
        print(f"Most recent match at line {count}: {reference[count-1][0]}: {reference[count-1][1]}")
        print(f"First divergence at line {count+1}.")
    else:
        print("No divergence detected.")

