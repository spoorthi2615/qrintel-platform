import os
import re

def replace_in_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Case insensitive replace "QRIntel" -> "QRIntel"
        # Case insensitive replace "QRIntel" -> "qrintel" (or QRIntel depending on case, but let's just do QRIntel)
        # We will do:
        # "QRIntel" -> "QRIntel"
        # "QRIntel" -> "QRIntel"
        # "QRIntel" -> "qrintel"
        # "QRIntel" -> "qrintel"
        
        new_content = content
        new_content = re.sub(r'QRIntel', 'QRIntel', new_content, flags=re.IGNORECASE)
        new_content = re.sub(r'QRIntel', 'QRIntel', new_content, flags=re.IGNORECASE)
        
        # for lower case
        new_content = re.sub(r'QRIntel', 'qrintel', new_content)
        new_content = re.sub(r'QRIntel', 'qrintel', new_content)

        if new_content != content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Updated: {filepath}")
    except Exception as e:
        pass

for root, dirs, files in os.walk(r"d:\projects\QRIntel"):
    if ".git" in root or "node_modules" in root or "__pycache__" in root or "venv" in root:
        continue
    for file in files:
        if file.endswith(('.py', '.md', '.json', '.jsx', '.html', '.css', '.js', '.txt')):
            replace_in_file(os.path.join(root, file))

print("Replacement complete.")
