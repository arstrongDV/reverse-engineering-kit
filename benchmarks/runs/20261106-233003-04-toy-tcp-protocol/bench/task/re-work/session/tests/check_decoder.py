import subprocess
import sys

failed = 0
for capture in sys.argv[1:]:
    run = subprocess.run([sys.executable, "-I", "decoder.py", capture], capture_output=True, text=True)
    failed += run.returncode != 0
    print(f"{'PASS' if run.returncode == 0 else 'FAIL'} {capture}: exit {run.returncode}")
    print(run.stdout, run.stderr)
sys.exit(1 if failed else 0)
