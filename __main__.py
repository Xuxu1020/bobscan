"""Top‑level entry point for ``python -m bobscan``.

The original project places the real code inside the inner package
``bobscan.bobscan`` (i.e. ``bobscan/bobscan``).  By providing a ``__main__``
module at the outer level that simply forwards to the inner CLI we make the
README's one‑liner work without any extra installation steps.
"""

from bobscan.bobscan.cli import main as _cli_main

if __name__ == "__main__":
    _cli_main()

