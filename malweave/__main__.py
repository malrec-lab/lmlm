"""Allow `python -m malweave` to invoke the project CLI."""

from malweave.cli import main

raise SystemExit(main())
