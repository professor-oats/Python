#!/usr/bin/env python3
"""
Render page with images: Fetch a URL, extract images, download them with curl, and embed locally.
Works even if Playwright browser dependencies are missing.

Usage: python3 renderpage_with_images.py <url> <output.html>
"""

import sys
import os
import re
import hashlib
import urllib.parse
import subprocess
from pathlib import Path


def download_image(url: str, output_dir: Path) -> str | None:
    """Download an image using curl and save it locally with subdirectory structure.
    
    Returns the relative path to the saved image if successful, None otherwise."""
    try:
        # Use curl to download with follow redirects
        result = subprocess.run(
            ["curl", "-L", "-s", "-f", "-o", "/dev/stdout", url],
            capture_output=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return None
        
        # Determine content type from curl headers if available
        content_type = ""
        # Try to get content-type via curl -I (headers only)
        head = subprocess.run(
            ["curl", "-L", "-s", "-I", url],
            capture_output=True,
            text=True,
            timeout=15
        )
        for line in head.stdout.split('\n'):
            if line.lower().startswith('content-type:'):
                content_type = line.split(':', 1)[1].strip().lower()
                break
        
        # Generate a safe path (preserve subdirectory structure from URL)
        url_path = urllib.parse.urlparse(url).path
        # Get the path relative to the root domain (remove first 'images' directory)
        path_parts = Path(url_path).parts[1:]  # Remove leading '/' from parts
        
        # Skip the first 'images' part of the path if present
        if path_parts and path_parts[0] == 'images':
            path_parts = path_parts[1:]
        
        if not path_parts:
            rel_path = Path("image.png")
        else:
            rel_path = Path(*path_parts)
        
        # Ensure valid extension
        ext = rel_path.suffix.lower()
        if not ext:
            if "jpeg" in content_type or "jpg" in content_type:
                ext = ".jpg"
            elif "png" in content_type:
                ext = ".png"
            elif "gif" in content_type:
                ext = ".gif"
            elif "webp" in content_type:
                ext = ".webp"
            elif "svg" in content_type:
                ext = ".svg"
            else:
                ext = ".png"
        
        if ext == ".jpeg":
            ext = ".jpg"

        # Sanitize each path component (only replace chars that would break paths)
        sanitized_parts = []
        for part in rel_path.parts:
            stem, extension = os.path.splitext(part)
            # Keep alphanumeric, underscore, hyphen, and dot for extensions
            stem = re.sub(r"[^\w\-]", "_", stem)
            # Keep dot and alphanumeric for extension
            extension = re.sub(r"[^\w\.\-]", "", extension)
            sanitized = stem + extension
            # Skip empty parts
            if sanitized and not sanitized.startswith('.'):
                sanitized_parts.append(sanitized)
        
        if not sanitized_parts:
            name_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            sanitized_parts = [f"image_{name_hash}{ext}"]
        
        # Create the relative path
        relative_path = Path(*sanitized_parts)
        
        # Ensure we have an extension if missing
        if not relative_path.suffix:
            relative_path = relative_path.with_suffix(ext)

        # Save the file with subdirectory structure
        local_path = output_dir / relative_path
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as f:
            f.write(result.stdout)
        
        # Return the relative path as a string
        return str(relative_path)
    except Exception as e:
        print(f"Warning: Failed to download image {url}: {e}")
        return None


def extract_image_urls(html: str, base_url: str) -> list[str]:
    """Extract image URLs from HTML using regex."""
    # Match img tags with src attribute
    pattern = r'<img[^>]+src=["\']([^"\']+)["\']'
    matches = re.findall(pattern, html, re.IGNORECASE)
    
    # Convert relative URLs to absolute
    absolute_urls = []
    for src in matches:
        abs_src = urllib.parse.urljoin(base_url, src)
        if abs_src not in absolute_urls:
            absolute_urls.append(abs_src)
    
    return absolute_urls


def fetch_html_with_curl(url: str) -> str:
    """Fetch HTML content from URL using curl."""
    result = subprocess.run(
        ["curl", "-s", url],
        capture_output=True,
        timeout=30
    )
    return result.stdout.decode('utf-8', errors='ignore')


def render_page_with_images(url: str, output: str):
    output_path = Path(output)
    output_dir = output_path.parent / "images"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Fetching page: {url}")

    # Try playwright first (if available) to get JS-rendered HTML
    playwright_success = False
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            # Try webkit first (original script used it), fallback to chromium
            browser = None
            for browser_name in ["webkit", "chromium"]:
                try:
                    browser = getattr(p, browser_name).launch(headless=True)
                    print(f"Launched {browser_name} browser")
                    break
                except Exception:
                    continue
            
            if browser:
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (X11; Linux x86_64) "
                        "AppleWebKit/605.1.15 "
                        "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
                    ),
                    locale="en-US",
                    java_script_enabled=True,
                )
                page = context.new_page()
                
                # Navigate to the page
                page.goto(url, wait_until="networkidle", timeout=60000)
                
                # Wait for additional JS
                page.wait_for_timeout(2000)
                
                # Extract image sources using JS for accuracy
                image_sources = page.evaluate("""
                    () => {
                        const images = Array.from(document.querySelectorAll('img'));
                        return images.map(img => img.src).filter(src => src);
                    }
                """)
                
                browser.close()
                
                print(f"Found {len(image_sources)} images on the page")
                
                # Get final HTML with JS execution
                html = page.content()
                playwright_success = True
                
            else:
                raise RuntimeError("Could not launch any browser")
                
    except ImportError:
        print("Playwright not installed. Using curl fallback.")
    except Exception as e:
        print(f"Warning: Playwright failed ({e}). Using curl fallback.")
        html = fetch_html_with_curl(url)

    # If playwright succeeded, extract from playwright; otherwise, extract from HTML
    if playwright_success:
        image_sources = image_sources
    else:
        # Fetch HTML and extract images via regex
        html = fetch_html_with_curl(url)
        image_sources = extract_image_urls(html, url)
        print(f"Extracted {len(image_sources)} images via regex")

    # Download each image with curl
    downloaded_images = {}
    for src in image_sources:
        # Convert relative URLs to absolute (already done in extraction if not from playwright)
        abs_src = urllib.parse.urljoin(url, src)
        
        if abs_src not in downloaded_images:
            local_filename = download_image(abs_src, output_dir)
            if local_filename:
                downloaded_images[abs_src] = local_filename
                print(f"Downloaded: {abs_src} -> images/{local_filename}")

    # Replace image sources with local paths
    for remote_url, local_path in downloaded_images.items():
        # Extract just the path part from the remote URL
        remote_path = urllib.parse.urlparse(remote_url).path
        
        # Pattern for full remote URL (like https://0xrick.github.io/images/...)
        pattern1 = rf'(?<=src=["\'])({re.escape(remote_url)})(?=["\'])'
        replacement1 = rf'images/{local_path}'
        html = re.sub(pattern1, replacement1, html)
        
        # Pattern for absolute path starting with / (like /images/...)
        pattern2 = rf'(?<=src=["\'])(/{re.escape(remote_path.lstrip("/")[:-1])}/)(?=["\'])'
        replacement2 = rf'images/{local_path}'
        # Actually let's just match the full path starting with /
        pattern2 = rf'(?<=src=["\'])/{re.escape(remote_path.lstrip("/"))}(?=["\'])'
        replacement2 = rf'images/{local_path}'
        html = re.sub(pattern2, replacement2, html)

    # Write the HTML file
    with open(output, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Rendered page saved to: {output}")
    print(f"Images saved to: {output_dir}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 renderpage_with_images.py <url> <output.html>")
        sys.exit(1)

    render_page_with_images(sys.argv[1], sys.argv[2])
