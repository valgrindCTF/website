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
    python -m webbrowser http://localhost:8000
    cd build
    python -m http.server
