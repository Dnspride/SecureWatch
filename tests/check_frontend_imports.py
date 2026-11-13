import glob
import re
import os

frontend_dir = os.path.abspath("frontend/src")

service_exports = {}
for sf in glob.glob(os.path.join(frontend_dir, "services", "*.ts")):
    name = os.path.splitext(os.path.basename(sf))[0]
    content = open(sf, encoding="utf-8").read()
    exports = set(re.findall(r'export\s+(?:const|function|interface|type)\s+([A-Za-z0-9_]+)', content))
    service_exports[f"../services/{name}"] = exports
    service_exports[f"./services/{name}"] = exports
    service_exports[f"@/services/{name}"] = exports

print("Found service exports:")
for k, v in service_exports.items():
    if k.startswith("../services"):
        print(f"  {k}: {sorted(v)}")

broken = []
for tf in glob.glob(os.path.join(frontend_dir, "**", "*.tsx"), recursive=True):
    content = open(tf, encoding="utf-8").read()
    for m in re.finditer(r'import\s+\{([^}]+)\}\s+from\s+[\'\"]([^\'\"]+)[\'\"]', content):
        imports = [x.strip().split(" as ")[0].strip() for x in m.group(1).split(",")]
        path = m.group(2)
        if path in service_exports:
            available = service_exports[path]
            for imp in imports:
                if imp and imp not in available:
                    broken.append((tf, imp, path, available))

print(f"\nBroken imports found: {len(broken)}")
for tf, imp, path, av in broken:
    rel = os.path.relpath(tf, frontend_dir)
    print(f"  [{rel}] '{imp}' not in {path}. Available: {sorted(av)}")
