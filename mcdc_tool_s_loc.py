import logging
import os.path
from dataclasses import dataclass

log = logging.getLogger(__name__)

@dataclass
class SFileLoc:
    fname: str
    line: int
    col: int

@dataclass
class SFileLocMap:
    origin: SFileLoc
    inlines: list[SFileLoc]

def get_s_file_locations(fname: str) -> list[SFileLocMap]:
    if not os.path.exists(fname):
        log.warning(f"File {fname} does not exists")
        return []
    with open(fname, "rt") as f:
        lines: list[str] = f.readlines()
    ret: list[SFileLocMap] = []
    for line in lines:
        line = line.strip()
        if not line.startswith(".loc"):
            continue
        pos = line.find("// ")
        line = line[pos+3:]
        locs = _parse_nested_locs(line)
        origin = locs[-1]
        rest = locs[:-1]
        ret.append(SFileLocMap(origin, rest))

    return ret

def _parse_nested_locs(data: str) -> list[SFileLoc]:
    # TODO: Regexp will be faster
    pos = data.find(" @[ ")
    if pos == -1:
        return [_parse_loc(data)]

    if not data.endswith(" ]"):
        raise Exception(f"Can't find terminating sequence in {data}")

    outer = data[:pos]
    inner = data[pos + 4:-2]

    return _parse_nested_locs(inner) + [_parse_loc(outer)]

def _parse_loc(loc: str) -> SFileLoc:
    s = loc.split(":")
    match len(s):
        case 3:
            return SFileLoc(s[0], int(s[1]), int(s[2]))
        case 2:
            if s[1]=="0":
                #Special case...
                return SFileLoc(s[0], int(s[1]), 0)
            else:
                raise Exception(f"Incorrect number of fields to parse full location: {loc}")
        case _:
            raise Exception(f"Incorrect number of fields to parse full location: {loc}")

