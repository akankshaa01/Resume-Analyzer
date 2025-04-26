# utils/parser.py
import re

NAME_RE  = r'^[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}$' 
EMAIL_RE = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
   

def extract_email(text: str) -> str | None:
    found = re.search(EMAIL_RE, text)
    return found.group(0) if found else None


