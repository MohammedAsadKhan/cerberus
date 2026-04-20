import requests
import hashlib
import json
from bs4 import BeautifulSoup

url = "https://pages.nist.gov/800-63-3/sp800-63b.html"

print(f"Fetching: {url}")
resp = requests.get(url, timeout=15)
resp.raise_for_status()

soup = BeautifulSoup(resp.text, "lxml")

target_sections = ["5.1.1", "5.1.1.1", "5.1.1.2"]

extracted = {}
for section_id in target_sections:
    tag = soup.find(id=section_id) or soup.find("section", {"data-section": section_id})
    if tag:
        extracted[section_id] = tag.get_text(separator=" ", strip=True)
    else:
        for heading in soup.find_all(["h2", "h3", "h4"]):
            if section_id in heading.get_text():
                content = heading.get_text(separator=" ", strip=True)
                next_tag = heading.find_next_sibling()
                if next_tag:
                    content += " " + next_tag.get_text(separator=" ", strip=True)
                extracted[section_id] = content
                break

combined = json.dumps(extracted, sort_keys=True)
current_hash = hashlib.sha256(combined.encode()).hexdigest()

print(f"Sections extracted: {list(extracted.keys())}")
print(f"Content hash: {current_hash}")

with open("nist_current_hash.txt", "w") as f:
    f.write(current_hash)

with open("nist_content.json", "w") as f:
    json.dump(extracted, f, indent=2)
