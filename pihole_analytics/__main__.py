"""
Entry point for running pihole_analytics as a module.

Usage: python -m pihole_analytics
"""

from .cli import main

if __name__ == "__main__":
    exit(main())
