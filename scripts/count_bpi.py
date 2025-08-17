import subprocess
import sys
import os
import tempfile

def main(trace_txt, trace_bin):
    # Directory of this script (and strip_trace.py)
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Temporary stripped file
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        stripped_file = tmp.name

    # Run strip_trace.py using full path
    subprocess.run([sys.executable, os.path.join(script_dir, "strip_trace.py"), trace_txt, stripped_file], check=True)

    # Count instructions (one per line)
    with open(stripped_file, "r") as f:
        instr_count = sum(1 for _ in f)

    # Count bits in the binary trace
    bits_count = os.path.getsize(trace_bin) * 8

    # Print instructions, bits, and bits per instruction
    bpi = bits_count / instr_count if instr_count > 0 else 0
    print(f"Instructions: {instr_count}")
    print(f"Bits: {bits_count}")
    print(f"BPI: {bpi:.2f}")

    # Cleanup temporary stripped file
    os.remove(stripped_file)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <trace_log.txt> <trace.bin>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])