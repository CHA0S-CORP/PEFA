"""Command-line interface for pefa."""

import argparse
import sys
from pathlib import Path

from .deps import require_playwright, sync_playwright
from .pipeline import eml_to_png


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Forensic Analyzer — generates cyber-infographic PNGs and interactive HTML reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", nargs="?", default=None, help=".eml file or directory")
    parser.add_argument("-o", "--output", help="Output path")
    parser.add_argument("--web", action="store_true", help="Start browser-based web UI (no Playwright needed)")
    parser.add_argument("--port", type=int, default=8080, help="Port for --web server (default: 8080)")
    parser.add_argument("--width", type=int, default=1000, help="Viewport width (default: 1000)")
    parser.add_argument("--scale", type=float, default=1.5, help="Scale factor (default: 1.5)")
    parser.add_argument("--html", action="store_true", help="Also emit interactive HTML report")
    parser.add_argument("--gemini", action="store_true", help="Include Gemini AI phishing assessment (requires GEMINI_API_KEY)")
    parser.add_argument("--gemini-model", default="gemini-2.5-flash", help="Gemini model (default: gemini-2.5-flash)")
    parser.add_argument("--no-api", action="store_true", help="Skip all API lookups")
    args = parser.parse_args()

    if args.web:
        from .web import start_server
        start_server(
            port=args.port,
            do_api=not args.no_api,
            do_gemini=args.gemini,
            gemini_model=args.gemini_model,
        )
        return

    if args.input is None:
        parser.error("the following arguments are required: input (or use --web)")

    input_path = Path(args.input)

    if input_path.is_file():
        eml_to_png(
            str(input_path), args.output,
            width=args.width, scale=args.scale,
            do_api=not args.no_api, emit_html=args.html,
            do_gemini=args.gemini, gemini_model=args.gemini_model,
        )

    elif input_path.is_dir():
        eml_files = sorted(input_path.glob("*.eml"))
        if not eml_files:
            sys.exit(f"No .eml files in {input_path}")

        out_dir = Path(args.output).resolve() if args.output else (input_path / "reports").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        require_playwright()
        pw = sync_playwright().start()
        browser = pw.chromium.launch()

        for eml_file in eml_files:
            out_file = out_dir / eml_file.with_suffix(".png").name
            try:
                eml_to_png(
                    str(eml_file), str(out_file),
                    width=args.width, scale=args.scale,
                    do_api=not args.no_api, emit_html=args.html,
                    do_gemini=args.gemini, gemini_model=args.gemini_model,
                    playwright_ctx=(pw, browser),
                )
            except Exception as e:
                print(f"  \u2717 {eml_file.name} \u2014 {e}")

        browser.close()
        pw.stop()
        print(f"\nDone. Reports in: {out_dir}")
    else:
        sys.exit(f"Not found: {input_path}")
