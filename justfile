# List available commands
default:
    @just --list

# Build the static site
build:
    python build.py

# Install dependencies
install:
    python -m pip install -r requirements.txt

# Host the site locally
serve:
    cd build && python -m webbrowser http://localhost:8000 && python -m http.server
