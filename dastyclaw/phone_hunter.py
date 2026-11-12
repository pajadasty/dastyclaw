from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class PhoneIntelResult:
    raw_number: str
    cleaned_number: str
    is_valid_format: bool
    country_hint: Optional[str] = None
    whatsapp_link: Optional[str] = None
    telegram_link: Optional[str] = None
    notes: str = ""


# Country Calling Code Mapping
COUNTRY_PREFIXES = {
    "1": "USA / Canada (+1)",
    "44": "United Kingdom (+44)",
    "49": "Germany (+49)",
    "33": "France (+33)",
    "420": "Czech Republic (+420)",
    "421": "Slovakia (+421)",
    "48": "Poland (+48)",
    "43": "Austria (+43)",
    "39": "Italy (+39)",
    "34": "Spain (+34)",
    "380": "Ukraine (+380)",
    "91": "India (+91)",
    "81": "Japan (+81)",
    "61": "Australia (+61)",
    "55": "Brazil (+55)",
}


class PhoneHunter:
    """Lightweight OSINT profiler for phone numbers."""

    @classmethod
    def analyze(cls, phone: str) -> PhoneIntelResult:
        raw = phone.strip()
        # Clean non-digit characters except leading plus
        cleaned = re.sub(r"[^\d+]", "", raw)
        digits_only = re.sub(r"\D", "", cleaned)

        if not digits_only or len(digits_only) < 7 or len(digits_only) > 15:
            return PhoneIntelResult(
                raw_number=raw,
                cleaned_number=cleaned,
                is_valid_format=False,
                notes="Number format invalid (must be 7-15 digits).",
            )

        # Detect country hint
        country_hint = None
        for code, name in sorted(COUNTRY_PREFIXES.items(), key=lambda x: -len(x[0])):
            if digits_only.startswith(code):
                country_hint = name
                break

        wa_link = f"https://wa.me/{digits_only}"
        tg_link = f"https://t.me/+{digits_only}"

        return PhoneIntelResult(
            raw_number=raw,
            cleaned_number=f"+{digits_only}",
            is_valid_format=True,
            country_hint=country_hint or "International",
            whatsapp_link=wa_link,
            telegram_link=tg_link,
            notes=f"Valid international E.164 phone structure. Likely: {country_hint or 'Unknown Region'}",
        )
