import struct
import argparse
import pickle
from collections import defaultdict
from typing import Dict, List, Tuple, Any


class TestVector:
    def __init__(self, outcome, val_mask, eval_mask, exit_target=0,
                 hit_count = 0):
        self.outcome = outcome
        self.val = val_mask
        self.eval = eval_mask
        self.exit = exit_target
        self.hit_count = hit_count

TRACE_VERSION = 1

# typedef struct { char magic[8]; uint32_t version; uint64_t reserved;
#                  uint64_t num_cpus; } TraceFileHeader;
FILE_HEADER_FMT = '<8sIQQ'
FILE_HEADER_SIZE = struct.calcsize(FILE_HEADER_FMT)

# Record prefix per hashtable entry: trace_write(&hit_count...)
RECORD_PREFIX_FMT = '<QI'
RECORD_PREFIX_SIZE = struct.calcsize(RECORD_PREFIX_FMT)

# typedef struct { char uuid[36]; uint32_t num_records;
#                  uint64_t exit_target; } CondBranchHeader;
COND_BRANCH_HEADER_FMT = '<36sIQ'
COND_BRANCH_HEADER_SIZE = struct.calcsize(COND_BRANCH_HEADER_FMT)

# typedef struct { uint64_t addr; uint8_t cpsr_bits; } PendingCondEntry;
PENDING_COND_ENTRY_FMT = '<QB'
PENDING_COND_ENTRY_SIZE = struct.calcsize(PENDING_COND_ENTRY_FMT)


def _validate_header(file_handle) -> int:
    """
    Reads and validates the global file header.
    Returns the number of CPUs captured in the trace if valid, otherwise 0.
    """
    header_bytes = file_handle.read(FILE_HEADER_SIZE)
    if len(header_bytes) < FILE_HEADER_SIZE:
        print("[Error] Trace file is too small to contain a valid header.")
        return 0

    magic, version, _, num_cpus = struct.unpack(
        FILE_HEADER_FMT, header_bytes
    )

    magic_str = magic.decode('ascii', errors='ignore').rstrip('\x00')

    if magic_str != "BRTRACE":
        print(f"[Error] Invalid magic number: Expected 'BRTRACE', got "
              f"'{magic_str}'")
        return 0

    if version != TRACE_VERSION:
        print(f"[Error] Unsupported trace version: {version}")
        return 0

    return num_cpus


def _parse_payload(sig_data: bytes) -> Tuple[str, int, tuple]:
    """
    Parses a block of binary data condition executions in the trace buffer.
    """
    uuid_bytes, num_records, exit_target = struct.unpack_from(
        COND_BRANCH_HEADER_FMT, sig_data, 0
    )

    uuid_str = uuid_bytes.decode('ascii', errors='ignore').strip('\x00').strip()

    nodes = []
    offset = COND_BRANCH_HEADER_SIZE

    for _ in range(num_records):
        addr, flag = struct.unpack_from(
            PENDING_COND_ENTRY_FMT, sig_data, offset
        )
        nodes.append((addr, flag))
        offset += PENDING_COND_ENTRY_SIZE

    return uuid_str, exit_target, tuple(nodes)


def parse_brtrace(trace_file: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parses a QEMU branch trace file, validates its headers, and returns
    condition executions by their associated UUID string.
    """
    conditions = defaultdict(list)

    with open(trace_file, 'rb') as f:
        num_cpus = _validate_header(f)
        if num_cpus == 0:
            return conditions

        trace_id_counter = 1

        while True:
            record_prefix = f.read(RECORD_PREFIX_SIZE)

            if not record_prefix or len(record_prefix) < RECORD_PREFIX_SIZE:
                break

            hit_count, write_size = struct.unpack(
                RECORD_PREFIX_FMT, record_prefix
            )

            cond_exec_data = f.read(write_size)
            if len(cond_exec_data) < write_size:
                print(f"[Warning] Found truncated record payload at block ID "
                      f"{trace_id_counter}")
                break

            uuid_str, exit_target, nodes = _parse_payload(cond_exec_data)

            if nodes:
                conditions[uuid_str].append({
                    'hit_count': hit_count,
                    'exit_target': exit_target,
                    'nodes': nodes
                })

            trace_id_counter += 1

    return conditions


def load_dwarf_data(dwarf_pickle_file) -> dict[str, ExprTraceInfo]:
    with open(dwarf_pickle_file, "rb") as f:
        dwarf_infos = pickle.load(f)
    return {info.expr.uuid: info for info in dwarf_infos}


def _build_address_maps(dwarf_info) -> Dict[int, Tuple[int, Any]]:
    """Maps hardware addresses to a tuple of (AST leaf index, TracePoint)."""
    addr_map = {}

    for idx, tp in enumerate(dwarf_info.trace_points):
        addr_map[tp.addr] = (idx, tp)

    return addr_map


def _evaluate_test_vectors(
    uuid_str: str,
    variants: List[Dict[str, Any]],
    expr: Any,
    leafs: List[Any],
    addr_map: Dict[int, Tuple[int, Any]],
) -> List['TestVector']:
    """Injects hardware traces into the AST and resolves outcomes."""
    unique_test_vectors = {}

    for var in variants:
        path_signature = var['nodes']
        hit_count = var.get('hit_count', 1)

        if path_signature in unique_test_vectors:
            unique_test_vectors[path_signature].hit_count += hit_count
            continue

        val_mask = 0
        eval_mask = 0
        expr.reset_value()

        for addr, raw_flag in var['nodes']:
            if addr not in addr_map:
                continue

            leaf_idx, tp = addr_map[addr]

            logic_value = (
                not bool(raw_flag) if tp.inverted else bool(raw_flag)
            )

            eval_mask |= (1 << leaf_idx)
            if logic_value:
                val_mask |= (1 << leaf_idx)

            leaf = leafs[leaf_idx]
            leaf.set_value(logic_value)

        if eval_mask == 0:
            continue

        overall_outcome = 1 if expr.get_value() else 0

        unique_test_vectors[path_signature] = TestVector(
            outcome=overall_outcome,
            val_mask=val_mask,
            eval_mask=eval_mask,
            exit_target=var['exit_target'],
            hit_count=hit_count
        )

    return list(unique_test_vectors.values())


def _print_diag(uuid_str: str, test_vectors: List['TestVector']):
    """Prints bitmask and outcome diagnostics for a specific UUID."""
    print(f"\n[ DEBUG ] Evaluated Vectors for UUID: {uuid_str}")
    for idx, t in enumerate(test_vectors, 1):
        print(
            f"  -> TestVec {idx:2d} | Val Mask: {t.val:04b} | "
            f"Eval Mask: {t.eval:04b} | Outcome: {t.outcome} "
            f"(Exit: 0x{t.exit:x})"
        )
    print("-" * 60)

def _find_mcdc_pairs(
    test_vectors: List['TestVector'],
    leafs: List[Any]
) -> List[bool]:
    """Calculates independence pairs to prove MC/DC coverage."""
    num_conditions = len(leafs)
    pairs_found = [False] * num_conditions

    true_tvs = [t for t in test_vectors if t.outcome == 1]
    false_tvs = [t for t in test_vectors if t.outcome == 0]

    for i in range(num_conditions):
        target_bit = 1 << i
        pair_found = False

        for t1 in true_tvs:
            for t2 in false_tvs:
                # Ensure the target condition was evaluated in both vectors
                if not (t1.eval & target_bit) or not (t2.eval & target_bit):
                    continue

                # Ensure the condition actually flipped between the vectors
                if not ((t1.val ^ t2.val) & target_bit):
                    continue

                shared_eval = t1.eval & t2.eval
                diff = t1.val ^ t2.val

                # Prove independence: only the target bit caused the flip
                if (diff & shared_eval) == target_bit:
                    pair_found = True
                    pairs_found[i] = True
                    break

            if pair_found:
                break

    return pairs_found

def _find_branch_hits(
    test_vectors: List['TestVector'],
    num_conditions: int
) -> List[Tuple[int, int]]:
    """
    Calculates True/False evaluation counts for every individual condition
    """
    branch_hits = []

    for i in range(num_conditions):
        target_bit = 1 << i

        true_count = sum(
            getattr(t, 'hit_count', 1) for t in test_vectors
            if (t.eval & target_bit) and (t.val & target_bit)
        )

        false_count = sum(
            getattr(t, 'hit_count', 1) for t in test_vectors
            if (t.eval & target_bit) and not (t.val & target_bit)
        )

        branch_hits.append((true_count, false_count))

    return branch_hits

def process_mcdc_coverage(
    trace_data: Dict[str, Any],
    dwarf_map: Dict[str, Any]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Evaluates coverage by mapping QEMU traces to DWARF AST representations.
    """
    file_coverage = defaultdict(list)

    for uuid_str, variants in trace_data.items():
        if uuid_str not in dwarf_map:
            continue

        dwarf_info = dwarf_map[uuid_str]
        expr = dwarf_info.expr

        leafs = expr.get_leafs()

        addr_map = _build_address_maps(dwarf_info)

        test_vectors = _evaluate_test_vectors(
            uuid_str, variants, expr, leafs, addr_map
        )

        _print_diag(uuid_str, test_vectors)

        pairs_found = _find_mcdc_pairs(test_vectors, leafs)

        branch_hits = _find_branch_hits(test_vectors, len(leafs))

        if getattr(expr, 'loc', None) and getattr(expr.loc, 'file', None):
            file_coverage[expr.loc.file].append({
                'expr': expr,
                'leafs': leafs,
                'pairs_found': pairs_found,
                'branch_hits': branch_hits
            })

    return file_coverage

def _write_file_records(file_handle, filepath: str, expressions: List[Dict]):
    """Writes the LCOV formatted coverage data for a single source file."""
    file_handle.write(f"SF:{filepath}\n")

    unique_lines = set()

    branches_found = 0
    branches_hit = 0

    for expr_data in expressions:
        expr = expr_data['expr']
        leafs = expr_data['leafs']
        pairs_found = expr_data['pairs_found']
        branch_hits = expr_data['branch_hits']

        loc = getattr(expr, 'loc', None)
        line_num = getattr(loc, 'line', 1) if loc else 1

        unique_lines.add(line_num)
        num_leafs = len(leafs)

        # Write Branch Coverage
        branch_id = 0
        for true_hits, false_hits in branch_hits:
            file_handle.write(
                f"BRDA:{line_num},0,{branch_id},{true_hits}\n"
            )
            branch_id += 1

            file_handle.write(
                f"BRDA:{line_num},0,{branch_id},{false_hits}\n"
            )
            branch_id += 1

            branches_found += 2
            branches_hit += (1 if true_hits > 0 else 0)
            branches_hit += (1 if false_hits > 0 else 0)

        # Write MCDC Coverage
        for i, leaf in enumerate(leafs):
            is_covered = 1 if pairs_found[i] else 0

            expr_str = str(leaf).replace(',', ' ')

            file_handle.write(
                f"MCDC:{line_num},{num_leafs},t,{is_covered},{i},{expr_str}\n"
            )
            file_handle.write(
                f"MCDC:{line_num},{num_leafs},f,{is_covered},{i},{expr_str}\n"
            )

    # WA: Write executed line data
    for line in sorted(unique_lines):
        file_handle.write(f"DA:{line},1\n")

    file_handle.write(f"BRF:{branches_found}\n")
    file_handle.write(f"BRH:{branches_hit}\n")

    file_handle.write(f"LF:{len(unique_lines)}\n")
    file_handle.write(f"LH:{len(unique_lines)}\n")
    file_handle.write("end_of_record\n")


def generate_lcov(
    file_coverage: Dict[str, List[Dict]],
    output_file: str = "coverage.info"
):
    """
    Generates an LCOV formatted coverage report from the evaluated MC/DC data.
    """
    with open(output_file, 'w') as f:
        f.write("TN:MCDC_Test_Report\n")

        for filepath, expressions in file_coverage.items():
            _write_file_records(f, filepath, expressions)

    print(f"\n[+] Successfully generated LCOV report at '{output_file}'")


def _parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments for the MC/DC tool."""
    parser = argparse.ArgumentParser(
        description=("MC/DC Coverage Report Generation Tool ")
    )

    parser.add_argument(
        "trace_files",
        nargs='+',
        help="One or more paths to brtrace.dat files"
    )
    parser.add_argument(
        "--dwarf",
        default="mcdc-dwarf.pickle",
        help="Path to mcdc-dwarf.pickle"
    )
    parser.add_argument(
        "--lcov",
        default="coverage.info",
        help="Output LCOV file name"
    )

    return parser.parse_args()


def _merge_trace_data(trace_files: List[str]) -> Dict[str, List[Any]]:
    """Parses and merges multiple QEMU trace files into a single dictionary."""
    merged_trace_data = defaultdict(list)

    for t_file in trace_files:
        file_data = parse_brtrace(t_file)
        for uuid_str, variants in file_data.items():
            merged_trace_data[uuid_str].extend(variants)

    return merged_trace_data


def main():
    args = _parse_arguments()

    print("[*] Loading DWARF TracePoints for AST Resolution...")
    dwarf_map = load_dwarf_data(args.dwarf)

    num_files = len(args.trace_files)
    print(f"[*] Parsing and merging {num_files} QEMU execution trace(s)...")
    merged_trace_data = _merge_trace_data(args.trace_files)

    print("\n[*] Analyzing Path Vectors and Executing Independence Proofs...")
    coverage_data = process_mcdc_coverage(merged_trace_data, dwarf_map)

    generate_lcov(coverage_data, args.lcov)

if __name__ == "__main__":
    main()
