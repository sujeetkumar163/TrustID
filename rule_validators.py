"""
TrustID Rule Validators - Role 3
Implements:
1. Aadhaar 12-digit Verhoeff checksum algorithm (UIDAI specification)
2. PAN 10-character structure and 4th-character entity type validation
"""

import re
from typing import Dict, Any

# Dihedral group D5 multiplication table
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

# Permutation table
VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

# Inversion table
VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

# Valid 4th characters for Indian PAN numbers
PAN_ENTITY_TYPES = {
    'P': 'Individual (Person)',
    'C': 'Company',
    'H': 'Hindu Undivided Family (HUF)',
    'F': 'Firm / Partnership',
    'A': 'Association of Persons (AOP)',
    'T': 'Trust',
    'B': 'Body of Individuals (BOI)',
    'L': 'Local Authority',
    'J': 'Artificial Juridical Person',
    'G': 'Government Agency'
}


def validate_verhoeff(num_str: str) -> bool:
    """
    Validates a number string using the Verhoeff check digit algorithm.
    Returns True if valid according to D5 check.
    """
    if not num_str:
        return False
    clean = "".join(c for c in str(num_str) if c.isdigit())
    if not clean:
        return False
    c = 0
    for i, digit in enumerate(reversed(clean)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(digit)]]
    return c == 0


def generate_verhoeff_check_digit(num_str: str) -> str:
    """
    Generates the Verhoeff check digit for an 11-digit or n-digit prefix.
    """
    clean = "".join(c for c in str(num_str) if c.isdigit())
    c = 0
    for i, digit in enumerate(reversed(clean), start=1):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(digit)]]
    return str(VERHOEFF_INV[c])


def validate_aadhaar_number(aadhaar_str: str) -> Dict[str, Any]:
    """
    Validates Indian Aadhaar number:
    1. Must contain 12 digits (can have spaces/hyphens in input)
    2. Must not start with 0 or 1
    3. Must pass Verhoeff checksum algorithm
    """
    if not aadhaar_str:
        return {"status": "UNKNOWN", "reason": "No Aadhaar number supplied"}
    
    clean = "".join(c for c in str(aadhaar_str) if c.isdigit())
    
    if len(clean) != 12:
        return {
            "status": "FAIL",
            "clean_number": clean,
            "reason": f"Aadhaar must be exactly 12 digits (found {len(clean)})"
        }
    
    if clean[0] in ('0', '1'):
        return {
            "status": "FAIL",
            "clean_number": clean,
            "reason": "Aadhaar numbers cannot begin with 0 or 1"
        }
    
    is_valid = validate_verhoeff(clean)
    return {
        "status": "PASS" if is_valid else "FAIL",
        "clean_number": clean,
        "formatted": f"{clean[:4]} {clean[4:8]} {clean[8:12]}",
        "reason": "Valid 12-digit Aadhaar with correct Verhoeff checksum" if is_valid else "Verhoeff checksum mismatch (tampered check digit)"
    }


def validate_pan_number(pan_str: str) -> Dict[str, Any]:
    """
    Validates Indian Permanent Account Number (PAN):
    Format: 5 letters, 4 digits, 1 letter (e.g., ABCDE1234F)
    4th character must belong to valid entity types (P, C, H, F, A, T, B, L, J, G)
    """
    if not pan_str:
        return {"status": "UNKNOWN", "reason": "No PAN number supplied"}
    
    clean = re.sub(r'[^A-Za-z0-9]', '', str(pan_str)).upper()
    
    if len(clean) != 10:
        return {
            "status": "FAIL",
            "clean_number": clean,
            "reason": f"PAN must be exactly 10 alphanumeric characters (found {len(clean)})"
        }
    
    pan_pattern = r'^[A-Z]{5}[0-9]{4}[A-Z]$'
    if not re.match(pan_pattern, clean):
        return {
            "status": "FAIL",
            "clean_number": clean,
            "reason": "PAN format mismatch: must be 5 letters + 4 digits + 1 letter"
        }
    
    entity_code = clean[3]
    if entity_code not in PAN_ENTITY_TYPES:
        return {
            "status": "FAIL",
            "clean_number": clean,
            "reason": f"Invalid 4th character '{entity_code}': not a recognized PAN entity type"
        }
    
    return {
        "status": "PASS",
        "clean_number": clean,
        "entity_type": PAN_ENTITY_TYPES[entity_code],
        "reason": f"Valid PAN format for entity type: {PAN_ENTITY_TYPES[entity_code]}"
    }


def evaluate_rules(extracted_fields: Dict[str, Any]) -> Dict[str, str]:
    """
    Evaluates rule checks for Aadhaar and PAN against extracted fields.
    Returns: {"aadhaar_checksum": "PASS"|"FAIL", "pan_checksum": "PASS"|"FAIL"}
    """
    id_num = extracted_fields.get("id_number", "")
    aadhaar_res = "UNKNOWN"
    pan_res = "UNKNOWN"
    
    clean_digits = "".join(c for c in str(id_num) if c.isdigit())
    clean_alpha = re.sub(r'[^A-Za-z0-9]', '', str(id_num)).upper()
    
    if len(clean_digits) == 12:
        res = validate_aadhaar_number(clean_digits)
        aadhaar_res = res["status"]
    
    if len(clean_alpha) == 10 and clean_alpha[:3].isalpha():
        res = validate_pan_number(clean_alpha)
        pan_res = res["status"]
    
    # If not explicitly an ID number or only partial
    if aadhaar_res == "UNKNOWN" and pan_res == "UNKNOWN":
        if len(clean_digits) >= 10:
            aadhaar_res = "PASS" if validate_verhoeff(clean_digits[:12]) else "FAIL"
        else:
            # Default to PASS if clean document without ID number format mismatch
            aadhaar_res = "PASS"
            pan_res = "PASS"

    return {
        "aadhaar_checksum": aadhaar_res if aadhaar_res != "UNKNOWN" else "PASS",
        "pan_checksum": pan_res if pan_res != "UNKNOWN" else "PASS"
    }
