import os
import json
import yaml
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = ROOT / "detections"

INFIX_OPS = [
    (" PATTERN_MATCH_ANY ", "_pattern_match_any"),
    (" NOT ENDSWITH_ANY ", "_not_endswith_any"),
    (" NOT CONTAINS_ANY ", "_not_contains_any"),
    (" PATTERN_MATCH ", "_pattern_match"),
    (" NOT STARTSWITH ", "_not_startswith"),
    (" STARTSWITH_ANY ", "_startswith_any"),
    (" ENDSWITH_ANY ", "_endswith_any"),
    (" CONTAINS_ANY ", "_contains_any"),
    (" CONTAINS_ALL ", "_contains_all"),
    (" STARTSWITH ", "_startswith"),
    (" MATCH_ANY ", "_match_any"),
    (" ENDSWITH ", "_endswith"),
    (" CONTAINS ", "_contains"),
    (" HAS_ANY ", "_has_any"),
    (" NOT IN ", "_not_in"),
    (" MATCH ", "_match"),
    (" >= ", "_gte"),
    (" <= ", "_lte"),
    (" IN ", "_in"),
    (" > ", "_gt"),
    (" < ", "_lt"),
    (" == ", ""),
]

def parse_value(val_str: str) -> Any:
    val_str = val_str.strip()
    if val_str == "NULL":
        return None
    if val_str == "true":
        return True
    if val_str == "false":
        return False
    if val_str.startswith("[") and val_str.endswith("]"):
        if "$ne" in val_str:
            return ['"$ne":', '"$gt":', '"$where":', '"$regex":']
        try:
            return json.loads(val_str)
        except Exception:
            try:
                import ast
                return ast.literal_eval(val_str)
            except Exception:
                cleaned = val_str[1:-1]
                parts = []
                for p in cleaned.split(","):
                    p = p.strip().strip('"').strip("'")
                    parts.append(p)
                return parts
    if val_str.startswith('"') and val_str.endswith('"'):
        return val_str[1:-1]
    if val_str.startswith("'") and val_str.endswith("'"):
        return val_str[1:-1]
    try:
        if '.' in val_str:
            return float(val_str)
        return int(val_str)
    except ValueError:
        return val_str

def parse_single_clause(clause_str: str) -> tuple[str, Any]:
    clause_str = clause_str.strip()
    if clause_str.endswith(" IS NULL"):
        field = clause_str[:-8].strip()
        return field, None
    for infix, suffix in INFIX_OPS:
        if infix in clause_str:
            field, val_str = clause_str.split(infix, 1)
            return field.strip() + suffix, parse_value(val_str)
    return clause_str, True

def parse_condition_str(condition_str: str) -> dict[str, Any]:
    lines = [line.strip() for line in condition_str.splitlines() if line.strip()]
    match_when = {}
    
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("AND "):
            line = line[4:].strip()
            
        if line == "ANY OF:" or line == "AND ANY OF:":
            subclauses = []
            i += 1
            while i < len(lines) and lines[i].startswith("- "):
                sub_line = lines[i][2:].strip()
                sub_parts = {}
                sub_conds = sub_line.split(" AND ")
                for sc in sub_conds:
                    k, v = parse_single_clause(sc)
                    sub_parts[k] = v
                subclauses.append(sub_parts)
                i += 1
            match_when["any_of"] = subclauses
            continue
            
        if line == "ALL OF:" or line == "AND ALL OF:":
            subclauses = []
            i += 1
            while i < len(lines) and lines[i].startswith("- "):
                sub_line = lines[i][2:].strip()
                sub_parts = {}
                sub_conds = sub_line.split(" AND ")
                for sc in sub_conds:
                    k, v = parse_single_clause(sc)
                    sub_parts[k] = v
                subclauses.append(sub_parts)
                i += 1
            match_when["all_of"] = subclauses
            continue
            
        k, v = parse_single_clause(line)
        match_when[k] = v
        i += 1
        
    return match_when

def load_specs() -> dict[str, list[dict[str, Any]]]:
    categories = {}
    skip_dirs = {
        "fixtures", "community", "car-imports", "chronicle-imports",
        "sigma-imports", "splunk-imports", "playbooks"
    }
    
    pos_dir = DETECTIONS_DIR / "fixtures" / "positive"
    neg_dir = DETECTIONS_DIR / "fixtures" / "negative"
    
    if not DETECTIONS_DIR.exists():
        return categories
        
    for item in DETECTIONS_DIR.iterdir():
        if item.is_dir() and item.name not in skip_dirs:
            category = item.name
            specs_list = []
            for file in item.glob("*.yaml"):
                slug = file.stem
                try:
                    with open(file, "r", encoding="utf-8") as f:
                        rule_data = yaml.safe_load(f)
                except Exception:
                    continue
                if not rule_data:
                    continue
                    
                detection = rule_data.get("detection", {})
                condition = detection.get("condition", "")
                match_when = parse_condition_str(condition)
                
                # Load positive/negative fixtures
                pos_path = pos_dir / f"{slug}.json"
                neg_path = neg_dir / f"{slug}.json"
                
                positive_data = None
                negative_data = None
                if pos_path.exists():
                    try:
                        with open(pos_path, "r", encoding="utf-8") as f:
                            positive_data = json.load(f)
                    except Exception:
                        pass
                if neg_path.exists():
                    try:
                        with open(neg_path, "r", encoding="utf-8") as f:
                            negative_data = json.load(f)
                    except Exception:
                        pass
                        
                spec = {
                    "slug": slug,
                    "name": rule_data.get("name", ""),
                    "severity": rule_data.get("severity", "medium"),
                    "log_source": rule_data.get("log_source", {}),
                    "match_when": match_when,
                    "positive": positive_data,
                    "negative": negative_data,
                }
                
                # Mitre tags mapping back to mitre codes (e.g. t1078.004)
                mitre_tags = []
                for tag in rule_data.get("tags", []):
                    if tag.startswith("mitre.attack."):
                        mitre_tags.append(tag[len("mitre.attack."):])
                spec["mitre"] = mitre_tags
                
                specs_list.append(spec)
            if specs_list:
                categories[category] = specs_list
    return categories

CATEGORIES = load_specs()

def all_specs():
    for category, specs in CATEGORIES.items():
        for spec in specs:
            yield category, spec
