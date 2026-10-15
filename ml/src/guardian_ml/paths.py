"""
Path resolution utilities for Guardian ML.

Resolves paths from GUARDIAN_HOME environment variable or package location.
Works from any working directory and inside Docker.
"""
import os
from pathlib import Path


def get_guardian_home() -> Path:
    """
    Get the Guardian home directory.
    
    Priority:
    1. GUARDIAN_HOME environment variable
    2. Package parent directory (when installed)
    3. Current working directory (fallback)
    
    Returns:
        Path to Guardian home directory
    """
    # 1. Check environment variable
    env_home = os.environ.get("GUARDIAN_HOME")
    if env_home:
        return Path(env_home).resolve()
    
    # Find the repository root from either the installed source tree or cwd.
    for candidate in (Path(__file__).resolve(), Path.cwd().resolve()):
        for parent in candidate.parents:
            if (parent / "ml" / "src" / "guardian_ml").is_dir():
                return parent

    return Path.cwd().resolve()


def resolve_path(relative_path: str | Path, base: Path | None = None) -> Path:
    """
    Resolve a relative path against the Guardian home directory.
    
    Args:
        relative_path: Path relative to Guardian home
        base: Optional base directory (defaults to Guardian home)
        
    Returns:
        Absolute resolved path
    """
    if base is None:
        base = get_guardian_home()
    
    path = Path(relative_path)
    if path.is_absolute():
        return path.resolve()
    
    return (base / path).resolve()


# Common path getters
def get_data_dir() -> Path:
    """Get data directory."""
    return resolve_path("ml/data")


def get_raw_data_dir() -> Path:
    """Get raw data directory."""
    return resolve_path("ml/data/raw")


def get_processed_data_dir() -> Path:
    """Get processed data directory."""
    return resolve_path("ml/data/processed")


def get_snapshot_dir() -> Path:
    """Get snapshot directory."""
    return resolve_path("ml/data/snapshots")


def get_model_dir() -> Path:
    """Get model directory."""
    return resolve_path("ml/models")


def get_api_models_dir() -> Path:
    """Get API models directory."""
    home = get_guardian_home()
    api_root = home / "api"
    if not api_root.is_dir() and (home / "src" / "main.py").is_file():
        api_root = home
    return api_root / "models"


def get_features_dir() -> Path:
    """Get features directory."""
    return resolve_path("ml/features")


def get_evaluation_dir() -> Path:
    """Get evaluation directory."""
    return resolve_path("ml/evaluation")


def get_logs_dir() -> Path:
    """Get logs directory."""
    return resolve_path("ml/logs")


# For backward compatibility
DEFAULT_PATHS = {
    "data_dir": "ml/data",
    "raw_data_dir": "ml/data/raw",
    "processed_data_dir": "ml/data/processed",
    "snapshot_dir": "ml/data/snapshots",
    "model_dir": "ml/models",
    "api_models_dir": "api/models",
    "features_dir": "ml/features",
    "evaluation_dir": "ml/evaluation",
    "logs_dir": "ml/logs",
}


if __name__ == "__main__":
    print(f"Guardian Home: {get_guardian_home()}")
    print(f"Data Dir: {get_data_dir()}")
    print(f"Model Dir: {get_model_dir()}")
    print(f"API Models Dir: {get_api_models_dir()}")