"""
upi_validator.py
Validates UPI (Unified Payments Interface) QR payload strings.
Checks for required fields, format correctness, and suspicious patterns.
"""

import re
import urllib.parse


VPA_PATTERN = re.compile(r'^[a-zA-Z0-9.\-_]+@[a-zA-Z0-9]+$')

SUSPICIOUS_VPA_KEYWORDS = [
    'refund', 'cashback', 'prize', 'lottery', 'free', 'offer',
    'winner', 'reward', 'lucky', 'gift',
]


def validate_upi_payload(payload: str) -> dict:
    """
    Validate a UPI payment QR string.

    UPI format: upi://pay?pa=VPA&pn=Name&am=Amount&cu=Currency&...

    Args:
        payload: The raw UPI string from a QR code.

    Returns:
        Dict with: score (0-100), status, reasons, fields.
    """
    score = 0
    reasons = []
    fields = {}

    if not payload:
        return {'score': 100, 'status': 'MALICIOUS', 'reasons': ['Empty payload'], 'fields': {}}

    pl = payload.strip()

    # Check scheme
    if not (pl.lower().startswith('upi://pay') or pl.lower().startswith('upi://')):
        return {
            'score': 100,
            'status': 'MALICIOUS',
            'reasons': ['Not a valid UPI scheme (must start with upi://pay)'],
            'fields': {},
        }

    try:
        parsed = urllib.parse.urlparse(pl)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # Flatten single-value lists
        flat = {k: v[0] if v else '' for k, v in params.items()}
        fields = flat

        # --- Required: pa (Payee VPA) ---
        pa = flat.get('pa', '')
        if not pa:
            score += 70  # CRITICAL: missing payee address
            reasons.append('Missing required field: pa (Payee VPA address)')
        else:
            if not VPA_PATTERN.match(pa):
                score += 40
                reasons.append(f'Malformed VPA address: "{pa}" (expected format: name@provider)')
            # Check for suspicious VPA keywords
            for kw in SUSPICIOUS_VPA_KEYWORDS:
                if kw in pa.lower():
                    score += 65  # Pushes firmly into MALICIOUS
                    reasons.append(f'Suspicious keyword in VPA address: "{kw}"')
                    break

        # --- Required: pn (Payee Name) ---
        pn = flat.get('pn', '')
        if not pn:
            score += 20
            reasons.append('Missing field: pn (Payee Name)')
        elif len(pn) < 2:
            score += 10
            reasons.append('Payee name is suspiciously short')
        else:
            # Also scan payee name for suspicious keywords
            for kw in SUSPICIOUS_VPA_KEYWORDS:
                if kw in pn.lower():
                    score += 30
                    reasons.append(f'Suspicious keyword in payee name: "{kw}"')
                    break


        # --- Optional but important: am (Amount) ---
        am = flat.get('am', '')
        if am:
            try:
                amount = float(am)
                if amount <= 0:
                    score += 35  # Raised: invalid/negative amount is suspicious
                    reasons.append(f'Invalid or negative amount value: {am}')
                elif amount > 100000:
                    score += 15
                    reasons.append(f'Very large pre-set amount: Rs.{amount:,.2f}')
            except ValueError:
                score += 25
                reasons.append(f'Non-numeric amount field: "{am}"')

        # --- Optional: cu (Currency) ---
        cu = flat.get('cu', 'INR')
        if cu and cu.upper() != 'INR':
            score += 15
            reasons.append(f'Non-standard currency: {cu} (expected INR)')

        # --- Optional: mc (Merchant Code) ---
        if not flat.get('mc'):
            # Not a hard error but worth noting
            pass

        # --- Check for unknown/suspicious extra params ---
        known_params = {'pa', 'pn', 'am', 'cu', 'mc', 'tid', 'tr', 'tn', 'url', 'mid', 'purpose', 'orgid'}
        unknown = set(flat.keys()) - known_params
        if unknown:
            score += min(len(unknown) * 10, 30)
            reasons.append(f'Unknown UPI parameters: {", ".join(unknown)}')

    except Exception as e:
        score += 70
        reasons.append(f'UPI parsing error: {str(e)}')

    score = min(score, 100)

    if score <= 30:
        status = 'SAFE'
    elif score <= 60:
        status = 'SUSPICIOUS'
    else:
        status = 'MALICIOUS'

    return {
        'score': score,
        'status': status,
        'reasons': reasons,
        'fields': fields,
    }
