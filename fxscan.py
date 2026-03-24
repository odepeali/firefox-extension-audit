import json
from pathlib import Path

FIREFOX_BASE = Path.home() / ".mozilla" / "firefox"

HIGH_RISK_PERMS = {
    "<all_urls>",
    "http://*/*", "https://*/*", "*://*/*",
    "tabs", "activeTab", "scripting",
    "webRequest", "webRequestBlocking",
    "declarativeNetRequest", "declarativeNetRequestWithHostAccess",
    "cookies", "storage", "unlimitedStorage",
    "proxy", "management", "nativeMessaging"
}

def normalize_perms(p):
    if isinstance(p, list):
        return p
    if isinstance(p, dict):
        out = []
        for v in p.values():
            if isinstance(v, list):
                out.extend(v)
        return out
    return []

def find_default_profile():
    for p in FIREFOX_BASE.glob("*.default*"):
        if (p / "extensions.json").exists():
            return str(p)
    return None

def scan_extensions(profile_path):
    ext_json_path = Path(profile_path) / "extensions.json"
    if not ext_json_path.exists():
        print("extensions.json not found in profile")
        return []

    try:
        data = json.loads(ext_json_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    addons = data.get("addons", [])
    results = []

    for addon in addons:
        if addon.get("type") != "extension":
            continue

        perms = normalize_perms(addon.get("permissions")) + normalize_perms(addon.get("optionalPermissions"))

        broad_hosts = any(p.endswith("/*") or p in HIGH_RISK_PERMS for p in perms)
        dangerous_apis = any(p in HIGH_RISK_PERMS for p in perms)

        flags = []
        if broad_hosts:
            flags.append("Broad host access detected")
        if dangerous_apis:
            flags.append("Dangerous permissions detected")

        results.append({
            "name": addon.get("defaultLocale", {}).get("name", "Unnamed"),
            "id": addon.get("id", "unknown"),
            "version": addon.get("version", "?"),
            "active": addon.get("active", False),
            "path": addon.get("path", "N/A"),
            "risk_flags": flags
        })

    return results

def main():
    profile = find_default_profile()
    if not profile:
        print("No Firefox profile with extensions found")
        return

    print("Profile:", profile)
    print()

    extensions = scan_extensions(profile)
    if not extensions:
        print("No extensions found")
        return

    print(f"Found {len(extensions)} extensions:\n")

    for ext in sorted(extensions, key=lambda x: len(x["risk_flags"]), reverse=True):
        risk_count = len(ext["risk_flags"])
        risk_tag = "HIGH RISK" if risk_count >= 2 else "Medium" if risk_count == 1 else "Low"
        status = "Active" if ext["active"] else "Disabled"

        print(f"[{risk_tag}] {ext['name']} ({status})")
        print(f"    ID     : {ext['id']}")
        print(f"    Version: {ext['version']}")
        print(f"    Path   : {ext['path']}")

        if ext["risk_flags"]:
            print("    Flags:")
            for flag in ext["risk_flags"]:
                print(f"      - {flag}")

        print("-" * 50)

    print("\nNote: This scan uses extensions.json only")

if __name__ == "__main__":
    main()