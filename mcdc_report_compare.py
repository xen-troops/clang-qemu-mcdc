import argparse
import sys
import os

def extract_mcdc_metrics(filepath: str) -> set:
    """Extracts MC/DC metrics into set for direct comparison."""
    coverage = set()
    current_file = "unknown"
    
    try:
        with open(filepath, 'rt') as f:
            for line in f:
                line = line.strip()
                if line.startswith("SF:"):
                    current_file = os.path.basename(line[3:])
                
                elif line.startswith("MCDC:"):
                    # Format: MCDC:<line_number>,<groupSize>,<sense>,<taken>,<index>,<expression>
                    parts = line[5:].split(',')
                    if len(parts) >= 5:
                        line_num = parts[0]
                        group_size = parts[1]
                        sense = parts[2]
                        taken = parts[3]
                        cond_index = parts[4]
                        
                        mcdc_string = f"SF:{current_file} | Line {line_num:03} | Cond {cond_index}/{group_size} | Sense: {sense.upper()} | Taken: {taken}"
                        coverage.add(mcdc_string)
                        
    except FileNotFoundError:
        print(f"Error: Could not find file {filepath}")
        sys.exit(2)
        
    return coverage

def main():
    parser = argparse.ArgumentParser(description="Compare MC/DC data using Set differences")
    parser.add_argument("baseline", help="Path to the reference .info file")
    parser.add_argument("new", help="Path to the generated .info file")
    args = parser.parse_args()

    baseline_set = extract_mcdc_metrics(args.baseline)
    new_set = extract_mcdc_metrics(args.new)

    if baseline_set == new_set:
        print(f"PASS: {args.new} matches baseline.")
        sys.exit(0)
    else:
        print(f"FAIL: MC/DC mismatch detected in {args.new}")
        print("-" * 80)
        
        # Items in baseline that are missing from the new report
        missing_in_new = sorted(baseline_set - new_set)
        for item in missing_in_new:
            print(f"- {item}")
            
        # Items in the new report that were not in the baseline
        extra_in_new = sorted(new_set - baseline_set)
        for item in extra_in_new:
            print(f"+ {item}")
            
        print("-" * 80)
        sys.exit(1)

if __name__ == '__main__':
    main()