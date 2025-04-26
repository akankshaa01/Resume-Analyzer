import re
from collections import defaultdict

SECTION_PATTERNS = {
    "summary": r"(summary|objective)",
    "education": r"(education|academic)",
    "experience": r"(experience|employment|work history)",
    "skills": r"(skills|technologies|technical)",
    "certifications": r"(certifications?|licenses?)",
    "projects": r"(projects?|academic projects?)",
}

def split_sections(text: str) -> dict[str, str]:
    """Return {section_name: section_text}."""
    lines = text.splitlines()
    current = "other"
    buckets = defaultdict(list)

    for line in lines:
        clean = line.strip().lower()
        # choose heading if matches a pattern
        for name, pat in SECTION_PATTERNS.items():
            if re.fullmatch(rf"\s*{pat}\s*[:\-]?", clean):
                current = name
                break
        else:
            buckets[current].append(line)

    return {k: "\n".join(v).strip() for k, v in buckets.items() if v}
