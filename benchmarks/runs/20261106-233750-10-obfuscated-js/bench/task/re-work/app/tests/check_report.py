import subprocess,sys
r=subprocess.run(["node","tests/check_report.js"],capture_output=True,text=True)
sys.stdout.write(r.stdout);sys.stderr.write(r.stderr)
sys.exit(r.returncode)
