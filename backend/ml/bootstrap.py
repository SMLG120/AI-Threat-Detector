"""
One-off init step: create the initial model bundle if none exists.
Run by the `init` service before the API starts:  python -m ml.bootstrap
"""
from loguru import logger

from ml.model_manager import ModelManager


def main():
    mm = ModelManager()
    if mm.bundle_path.exists():
        logger.info(f"Model bundle already present at {mm.bundle_path}")
        return
    mm.bootstrap(save=True)


if __name__ == "__main__":
    main()
