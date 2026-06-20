from PIL import Image, ImageDraw
import os

def create_clone():
    source_path = 'backend/assets/reference_logins/github.png'
    dest_path = 'backend/assets/reference_logins/evil_github.png'
    
    img = Image.open(source_path)
    draw = ImageDraw.Draw(img)
    
    # Draw a simulated fake overlay injection
    draw.rectangle([100, 100, 300, 150], fill="red")
    draw.text((110, 110), "STEALING YOUR PASSWORD", fill="white")
    
    img.save(dest_path)
    print(f"Created modified clone at {dest_path}")

if __name__ == "__main__":
    create_clone()
