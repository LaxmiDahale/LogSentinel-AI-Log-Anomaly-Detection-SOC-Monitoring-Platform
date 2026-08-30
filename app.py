import sys
from pathlib import Path

# Ensure project root is in python path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from dashboard.dashboard import main

if __name__ == "__main__":
    main()
