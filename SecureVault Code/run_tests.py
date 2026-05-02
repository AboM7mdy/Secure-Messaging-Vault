import subprocess
import sys

print("Running SecureVault functional tests...\n")

result = subprocess.run(
    [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
    capture_output=True,
    text=True
)

print(result.stdout)

if result.stderr:
    print(result.stderr)

sys.exit(result.returncode)