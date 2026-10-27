"""Check release archives for required public files and sensitive local paths."""

import argparse
import fnmatch
import posixpath
import re
import tarfile
import tomllib
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCUMENTS = (
    "README.md",
    "README-pypi.md",
    "CONTRIBUTING.md",
    "docs/architecture.md",
    "docs/configuration.md",
    "docs/roadmap.md",
    "docs/usage.md",
    "docs/validation.md",
)
REQUIRED_SDIST = frozenset(
    (
        *DOCUMENTS,
        "LICENSE",
        "main.py",
        "requirements.txt",
        "pyproject.toml",
        "MANIFEST.in",
        ".env.example",
        "panos-tunnel-builder.example.toml",
        ".github/workflows/ci.yml",
        "scripts/check_distributions.py",
    )
)
LOCAL_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def check_sensitive_paths(names: set[str], archive_name: str) -> None:
    for name in names:
        path = PurePosixPath(name)
        base = path.name.casefold()
        sensitive = (
            base in {".env", "panos-tunnel-builder.toml"}
            or "migration-snapshots" in {part.casefold() for part in path.parts}
            or base.endswith((".pem", ".key"))
            or fnmatch.fnmatch(base, "lsvpn_*_routes.json*")
            or fnmatch.fnmatch(base, "lsvpn_migration_*_validation.json*")
        )
        if sensitive:
            raise ValueError(f"{archive_name} contains a sensitive local path: {name}")


def check_metadata(content: bytes, readme: str, project: dict[str, object]) -> None:
    metadata = BytesParser(policy=policy.default).parsebytes(content)
    if metadata["Name"] != project["name"] or metadata["Version"] != project["version"]:
        raise ValueError(
            "Package metadata name or version does not match pyproject.toml"
        )
    if metadata["Description-Content-Type"] != "text/markdown":
        raise ValueError("Package metadata does not declare a Markdown README")
    if (
        not isinstance(metadata.get_payload(), str)
        or metadata.get_payload().strip() != readme.strip()
    ):
        raise ValueError("Package metadata does not contain the project README")
    urls = project["urls"]
    if not isinstance(urls, dict) or not {"Repository", "Documentation"} <= urls.keys():
        raise ValueError(
            "Project metadata must declare repository and documentation URLs"
        )
    actual_urls = metadata.get_all("Project-URL", [])
    for label in ("Repository", "Documentation"):
        expected = f"{label}, {urls[label]}"
        if expected not in actual_urls:
            raise ValueError(f"Package metadata is missing project URL: {label}")


def check_document_links(files: dict[str, bytes]) -> None:
    for name in DOCUMENTS:
        content = files[name].decode("utf-8")
        for match in LOCAL_LINK.finditer(content):
            target = match.group(1).strip().strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            path = posixpath.normpath(
                posixpath.join(posixpath.dirname(name), unquote(parsed.path))
            )
            if path not in files:
                raise ValueError(
                    f"{name} links to a missing source-archive file: {path}"
                )


def check_distributions(directory: Path) -> None:
    wheels, sdists = list(directory.glob("*.whl")), list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError(
            "Expected exactly one wheel and one source archive in the output directory"
        )
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())["project"]
    with tarfile.open(sdists[0], "r:gz") as archive:
        members = archive.getmembers()
        if any(member.issym() or member.islnk() for member in members):
            raise ValueError("Source archive contains a link")
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        if len(roots) != 1:
            raise ValueError("Source archive does not have one top-level directory")
        root = roots.pop()
        files = {
            member.name.removeprefix(root + "/"): archive.extractfile(member).read()
            for member in members
            if member.isfile()
        }
    missing = REQUIRED_SDIST - files.keys()
    if missing:
        raise ValueError(
            f"Source archive is missing required files: {', '.join(sorted(missing))}"
        )
    check_sensitive_paths(set(files), sdists[0].name)
    check_document_links(files)
    readme_name = project["readme"]
    if not isinstance(readme_name, str) or readme_name not in files:
        raise ValueError("Package README is missing from the source archive")
    readme = files[readme_name].decode("utf-8")
    for match in LOCAL_LINK.finditer(readme):
        if not urlsplit(match.group(1)).scheme:
            raise ValueError("Package README contains a relative link")
    check_metadata(files["PKG-INFO"], readme, project)
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        check_sensitive_paths(names, wheels[0].name)
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        licenses = [
            name for name in names if name.endswith(".dist-info/licenses/LICENSE")
        ]
        if len(metadata) != 1 or len(licenses) != 1:
            raise ValueError("Wheel must contain one metadata file and the license")
        check_metadata(archive.read(metadata[0]), readme, project)
        source_modules = {
            name.removeprefix("src/")
            for name in files
            if name.startswith("src/panos_tunnel_builder/") and name.endswith(".py")
        }
        missing_modules = source_modules - names
        if not source_modules or missing_modules:
            raise ValueError(
                f"Wheel is missing source modules: {', '.join(sorted(missing_modules))}"
            )
    print(f"Verified {sdists[0].name} and {wheels[0].name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "directory", type=Path, help="Directory containing the two build archives"
    )
    args = parser.parse_args()
    try:
        check_distributions(args.directory)
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"Distribution verification failed: {exc}\n")


if __name__ == "__main__":
    main()
