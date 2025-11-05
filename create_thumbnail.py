"""
Create thumbnail from main screenshot
"""
from PIL import Image
from pathlib import Path

def create_thumbnail():
    docs_dir = Path("docs/images")
    main_img_path = docs_dir / "main_interface.png"
    thumbnail_path = docs_dir / "screenshot.png"

    if main_img_path.exists():
        # Open and resize
        img = Image.open(main_img_path)
        img.thumbnail((1200, 800), Image.Resampling.LANCZOS)
        img.save(thumbnail_path, "PNG", optimize=True, quality=90)
        print(f"Thumbnail created: {thumbnail_path}")
        print(f"Size: {thumbnail_path.stat().st_size / 1024:.1f} KB")
        return True
    else:
        print(f"Source image not found: {main_img_path}")
        return False

if __name__ == "__main__":
    create_thumbnail()
