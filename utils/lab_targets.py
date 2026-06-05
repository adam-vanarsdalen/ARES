"""Manifest-backed target validation for local ARES demo labs."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from utils.config import LAB_MANIFEST_PATH


@dataclass
class LabManifest:
    docker_services: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    scenarios: list[str] = field(default_factory=list)
    source_path: str = ""


def load_lab_manifest(path: str = "") -> LabManifest:
    manifest_path = Path(path or LAB_MANIFEST_PATH)
    if not manifest_path.is_absolute():
        manifest_path = Path(__file__).resolve().parent.parent / manifest_path
    manifest_path = manifest_path.resolve()
    if not manifest_path.is_file():
        return LabManifest(source_path=str(manifest_path))
    with manifest_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    labs = raw.get("labs", raw)
    return LabManifest(
        docker_services=[str(item).lower().strip() for item in labs.get("docker_services", []) if str(item).strip()],
        cidrs=[str(item).strip() for item in labs.get("cidrs", []) if str(item).strip()],
        scenarios=[str(item).strip() for item in labs.get("scenarios", []) if str(item).strip()],
        source_path=str(manifest_path),
    )


def target_host(target: str) -> str:
    parsed = urlsplit(target if "://" in str(target) else f"//{target}")
    return (parsed.hostname or str(target)).lower().rstrip(".")


def is_lab_target(target: str, manifest: LabManifest | None = None) -> bool:
    host = target_host(target)
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return True
    manifest = manifest or load_lab_manifest()
    if host in manifest.docker_services:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    for cidr in manifest.cidrs:
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
