"""
SecureWatch Test Suite Runner
Executes all unit, integration, detection engine, and endpoint agent tests.
"""
import subprocess
import sys


TEST_MODULES = [
    ["python", "tests/test_detection_engine.py"],
    ["python", "tests/test_iam_rbac.py"],
    ["python", "endpoint-agent/tests/test_monitors.py"],
    ["python", "-m", "tests.e2e.test_platform_e2e"],
]


def main():
    print("=" * 65)
    print("       SECUREWATCH UNIFIED TEST SUITE RUNNER")
    print("=" * 65)

    passed = 0
    failed = 0

    for cmd in TEST_MODULES:
        cmd_str = " ".join(cmd)
        print(f"\n[*] Running: {cmd_str}")
        print("-" * 65)
        res = subprocess.run(cmd)
        if res.returncode == 0:
            passed += 1
        else:
            failed += 1
            print(f"[!] FAILED: {cmd_str} (exit code: {res.returncode})")

    print("\n" + "=" * 65)
    print(f" Summary: {passed} passed, {failed} failed out of {len(TEST_MODULES)} suites.")
    print("=" * 65)
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
