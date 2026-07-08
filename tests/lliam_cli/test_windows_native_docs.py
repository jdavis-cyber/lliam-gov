from pathlib import Path


def test_windows_native_install_path_docs_match_installer() -> None:
    doc = Path("website/docs/user-guide/windows-native.md").read_text()
    install = Path("scripts/install.ps1").read_text()

    assert "%LOCALAPPDATA%\\hermes\\hermes-agent\\venv\\Scripts" in doc
    assert "Get-Command lliam-gov     # should print C:\\Users\\<you>\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\lliam-gov.exe" in doc
    assert '$lliamBin = "$InstallDir\\venv\\Scripts"' in install
