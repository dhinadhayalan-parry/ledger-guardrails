#!/usr/bin/env python3
"""Keep controls/catalog.yaml and the policy code consistent in both directions.

Checks
  * catalog entries are well formed and have a mode for every environment
  * every control is enforced by at least one policy
  * every Terraform policy package declares the controls it enforces
    (METADATA custom.controls), the declaration matches the control IDs the
    package actually emits, the catalog points back at the package, and the
    package has a test package
  * every admission template is referenced by the catalog, carries matching
    control annotations and messages, has a constraint, and is covered by the
    gator suite
  * the control matrix in README.md is up to date

Usage
  scripts/traceability.py                 # check, exit 1 on any problem
  scripts/traceability.py --write-readme  # regenerate the README matrix
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

LOG = logging.getLogger("traceability")

CONTROL_ID = re.compile(r"^LG-[A-Z0-9]+-\d{2}$")
FINDING_CALL = re.compile(r'lib\.finding\(\s*"(LG-[A-Z0-9]+-\d{2})"')
TEMPLATE_MSG = re.compile(r"\[(LG-[A-Z0-9]+-\d{2})\]")
MODES = {"warn", "enforce"}
POLICY_PREFIX = ("data", "ledger", "terraform")
MATRIX_START = "<!-- control-matrix:start -->"
MATRIX_END = "<!-- control-matrix:end -->"


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)

    def error(self, msg: str) -> None:
        self.errors.append(msg)
        LOG.error(msg)


def load_yaml(path: Path) -> object:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc


def environments(root: Path) -> list[str]:
    envs = []
    for path in sorted((root / "config" / "envs").glob("*.yaml")):
        doc = load_yaml(path)
        if not isinstance(doc, dict) or doc.get("ledger_env") != path.stem:
            raise SystemExit(f"{path}: ledger_env must equal the file name ({path.stem})")
        envs.append(path.stem)
    if not envs:
        raise SystemExit("no environments found in config/envs")
    # Production last, so the matrix reads in promotion order.
    return sorted(envs, key=lambda env: (env == "prod", env))


def check_catalog(catalog: dict, envs: list[str], report: Report) -> None:
    for cid, ctl in catalog.items():
        if not CONTROL_ID.match(cid):
            report.error(f"catalog: {cid} does not match {CONTROL_ID.pattern}")
        if not isinstance(ctl, dict):
            report.error(f"catalog: {cid} must be a mapping")
            continue
        for key in ("title", "requirement", "frameworks", "enforcement", "mode", "owner"):
            if key not in ctl:
                report.error(f"catalog: {cid} is missing '{key}'")
        mode = ctl.get("mode") or {}
        for env in envs:
            if mode.get(env) not in MODES:
                report.error(f"catalog: {cid} mode.{env} must be one of {sorted(MODES)}, got {mode.get(env)!r}")
        for env in set(mode) - set(envs):
            report.error(f"catalog: {cid} has mode for unknown environment '{env}'")
        enforcement = ctl.get("enforcement") or {}
        if not any(enforcement.get(k) for k in ("pr_gate", "admission")):
            report.error(f"catalog: {cid} is not enforced by any policy")


def opa_inspect(opa: str, policy_dir: Path) -> dict:
    result = subprocess.run(
        [opa, "inspect", "--annotations", "--format", "json", str(policy_dir)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"opa inspect failed:\n{result.stderr}")
    return json.loads(result.stdout)


def package_name(path: list[dict]) -> str:
    return ".".join(p["value"] for p in path[1:])


def check_rego(root: Path, opa: str, catalog: dict, report: Report) -> dict[str, list[str]]:
    policy_dir = root / "policies" / "terraform"
    inspected = opa_inspect(opa, policy_dir)

    # namespaces: {"data.ledger.terraform.storage": ["file", ...], ...}
    packages: dict[str, list[Path]] = {}
    for ns, files in inspected.get("namespaces", {}).items():
        parts = tuple(ns.split("."))
        if parts[: len(POLICY_PREFIX)] == POLICY_PREFIX and not ns.endswith("_test"):
            packages[ns.removeprefix("data.")] = [Path(f) for f in files]
    test_packages = {ns.removeprefix("data.") for ns in inspected.get("namespaces", {}) if ns.endswith("_test")}

    declared: dict[str, list[str]] = {}
    for ann in inspected.get("annotations", []):
        if ann["annotations"].get("scope") != "package":
            continue
        pkg = package_name(ann["path"])
        if pkg in packages:
            declared[pkg] = list((ann["annotations"].get("custom") or {}).get("controls") or [])

    catalog_refs = {
        pkg: {cid for cid, ctl in catalog.items() if pkg in (ctl.get("enforcement") or {}).get("pr_gate", [])}
        for pkg in {p for ctl in catalog.values() for p in (ctl.get("enforcement") or {}).get("pr_gate", [])}
    }

    for pkg, files in sorted(packages.items()):
        controls = declared.get(pkg)
        if not controls:
            report.error(f"rego: package {pkg} has no METADATA custom.controls")
            continue
        emitted = set()
        for file in files:
            emitted |= set(FINDING_CALL.findall((root / file).read_text(encoding="utf-8")))
        if set(controls) != emitted:
            report.error(f"rego: {pkg} declares {sorted(controls)} but emits findings for {sorted(emitted)}")
        for cid in controls:
            if cid not in catalog:
                report.error(f"rego: {pkg} declares unknown control {cid}")
            elif pkg not in (catalog[cid].get("enforcement") or {}).get("pr_gate", []):
                report.error(f"catalog: {cid}.enforcement.pr_gate does not list {pkg}, which enforces it")
        if f"{pkg}_test" not in test_packages:
            report.error(f"rego: {pkg} has no test package {pkg}_test")

    for pkg, cids in sorted(catalog_refs.items()):
        if pkg not in packages:
            report.error(f"catalog: {sorted(cids)} reference missing Rego package {pkg}")
        else:
            for cid in cids:
                if cid not in (declared.get(pkg) or []):
                    report.error(f"catalog: {cid} lists {pkg}, but the package does not declare {cid}")

    return {pkg: declared.get(pkg, []) for pkg in packages}


def annotation_controls(doc: dict) -> set[str]:
    raw = ((doc.get("metadata") or {}).get("annotations") or {}).get("ledger.io/controls", "")
    return {c.strip() for c in raw.split(",") if c.strip()}


def check_admission(root: Path, catalog: dict, report: Report) -> None:
    k8s = root / "policies" / "kubernetes"
    templates: dict[str, tuple[Path, set[str]]] = {}
    for path in sorted((k8s / "templates").glob("*.yaml")):
        doc = load_yaml(path)
        kind = doc["spec"]["crd"]["spec"]["names"]["kind"]
        controls = annotation_controls(doc)
        templates[kind] = (path, controls)
        if not controls:
            report.error(f"admission: {path.name} has no ledger.io/controls annotation")
        rego = "\n".join(t.get("rego", "") for t in doc["spec"]["targets"])
        in_messages = set(TEMPLATE_MSG.findall(rego))
        if in_messages != controls:
            report.error(f"admission: {path.name} annotates {sorted(controls)} but messages cite {sorted(in_messages)}")
        for cid in controls:
            if cid not in catalog:
                report.error(f"admission: {path.name} references unknown control {cid}")
            elif kind not in (catalog[cid].get("enforcement") or {}).get("admission", []):
                report.error(f"catalog: {cid}.enforcement.admission does not list {kind}")

    constrained: dict[str, set[str]] = {}
    for path in sorted((k8s / "constraints").glob("*.yaml")):
        doc = load_yaml(path)
        constrained.setdefault(doc["kind"], set()).update(annotation_controls(doc))

    suite_templates = set()
    for suite in k8s.rglob("suite.yaml"):
        for test in (load_yaml(suite) or {}).get("tests", []):
            suite_templates.add((suite.parent / test["template"]).resolve())

    for kind, (path, controls) in templates.items():
        if kind not in constrained:
            report.error(f"admission: no constraint instantiates {kind}")
        elif constrained[kind] != controls:
            report.error(f"admission: constraint for {kind} annotates {sorted(constrained[kind])}, template {sorted(controls)}")
        if path.resolve() not in suite_templates:
            report.error(f"admission: {path.name} is not covered by a gator suite")

    for cid, ctl in catalog.items():
        for kind in (ctl.get("enforcement") or {}).get("admission", []):
            if kind not in templates:
                report.error(f"catalog: {cid} references missing admission template {kind}")


def render_matrix(catalog: dict, envs: list[str]) -> str:
    def join(values: list[str]) -> str:
        return ", ".join(values) if values else "-"

    header = ["Control", "Objective", "ISO 27001:2022", "SOC 2", "PR gate (Rego)", "Admission (AKS)"]
    header += [f"Mode: {env}" for env in envs]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for cid in sorted(catalog):
        ctl = catalog[cid]
        enforcement = ctl.get("enforcement") or {}
        frameworks = ctl.get("frameworks") or {}
        row = [
            f"`{cid}`",
            ctl["title"],
            join(frameworks.get("iso27001_2022", [])),
            join(frameworks.get("soc2", [])),
            join([f"`{p.rsplit('.', 1)[-1]}.rego`" for p in enforcement.get("pr_gate", [])]),
            join([f"`{k}`" for k in enforcement.get("admission", [])]),
        ]
        row += [ctl["mode"][env] for env in envs]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def sync_readme(root: Path, matrix: str, write: bool, report: Report) -> None:
    readme = root / "README.md"
    text = readme.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(MATRIX_START) + r".*?" + re.escape(MATRIX_END), re.S)
    if not pattern.search(text):
        report.error(f"README.md has no {MATRIX_START} ... {MATRIX_END} section")
        return
    updated = pattern.sub(f"{MATRIX_START}\n{matrix}\n{MATRIX_END}", text)
    if updated == text:
        return
    if write:
        readme.write_text(updated, encoding="utf-8")
        LOG.info("README.md control matrix regenerated")
    else:
        report.error("README.md control matrix is stale; run `make matrix` and commit the result")


def main() -> int:
    parser = argparse.ArgumentParser(description="Control catalog traceability checks")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--opa", default=shutil.which("opa") or "opa", help="path to the opa binary")
    parser.add_argument("--write-readme", action="store_true", help="regenerate the README control matrix")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)

    root = args.root.resolve()
    if shutil.which(args.opa) is None and not Path(args.opa).is_file():
        parser.error(f"opa binary not found: {args.opa}")

    doc = load_yaml(root / "controls" / "catalog.yaml")
    if not isinstance(doc, dict) or not isinstance(doc.get("controls"), dict):
        raise SystemExit("controls/catalog.yaml must contain a 'controls' mapping")
    catalog: dict = doc["controls"]
    envs = environments(root)

    report = Report()
    check_catalog(catalog, envs, report)
    packages = check_rego(root, args.opa, catalog, report)
    check_admission(root, catalog, report)
    sync_readme(root, render_matrix(catalog, envs), args.write_readme, report)

    if report.errors:
        LOG.error("%d traceability problem(s)", len(report.errors))
        return 1
    LOG.info(
        "OK: %d controls, %d Rego packages, environments %s",
        len(catalog), len(packages), ", ".join(envs),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
