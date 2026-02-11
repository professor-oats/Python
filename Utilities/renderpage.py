import sys
from playwright.sync_api import sync_playwright

def render_page(url: str, output: str):
    with sync_playwright() as p:
        browser = p.webkit.launch(
            headless=True
        )

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
        page.goto(url, wait_until="networkidle", timeout=30000)

        # Optional: give late JS a moment
        page.wait_for_timeout(1500)

        html = page.content()

        with open(output, "w", encoding="utf-8") as f:
            f.write(html)

        browser.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: render.py <url> <output.html>")
        sys.exit(1)

    render_page(sys.argv[1], sys.argv[2])
