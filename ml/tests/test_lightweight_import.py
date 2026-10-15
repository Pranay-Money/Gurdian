import os
import subprocess
import sys
from pathlib import Path


def test_guardian_model_import_does_not_require_matplotlib():
    source_path = Path(__file__).resolve().parents[1] / "src"
    environment = os.environ.copy()
    environment.update(
        OPENBLAS_NUM_THREADS="1",
        OMP_NUM_THREADS="1",
        MKL_NUM_THREADS="1",
    )
    script = """
import importlib.abc
import sys

sys.path.insert(0, sys.argv[1])

class BlockMatplotlib(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "matplotlib" or fullname.startswith("matplotlib."):
            raise ModuleNotFoundError("matplotlib intentionally blocked in this test")
        return None

blocker = BlockMatplotlib()
sys.meta_path.insert(0, blocker)
from guardian_ml import GuardianModel
assert GuardianModel.__name__ == "GuardianModel"
assert "guardian_ml.components.evaluation" not in sys.modules
assert "matplotlib.pyplot" not in sys.modules
from guardian_ml import ModelExporter
assert ModelExporter.__name__ == "ModelExporter"
print("GuardianModel import OK")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(source_path)],
        capture_output=True,
        check=False,
        text=True,
        env=environment,
        cwd=source_path.parent.parent,
    )

    assert result.returncode == 0, result.stderr
    assert "GuardianModel import OK" in result.stdout
