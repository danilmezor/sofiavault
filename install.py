#!/usr/bin/env python3
"""
Cross-platform installer for SofiaVault password manager
Works on macOS, Linux, and Windows
"""

import os
import subprocess
import sys
from pathlib import Path


def get_bin_dir():
    """Get the appropriate bin directory for the platform"""
    if sys.platform == 'win32':
        # Windows: use Scripts folder in user's Python
        return Path.home() / 'AppData' / 'Local' / 'Programs' / 'Python' / 'Scripts'
    else:
        # macOS/Linux: use ~/.local/bin
        return Path.home() / '.local' / 'bin'

def main():
    print("\n♥ Installing SofiaVault Password Manager ♥\n")

    # Install dependencies
    print("Installing dependencies...")
    subprocess.check_call([
        sys.executable, '-m', 'pip', 'install', '-q',
        'argon2-cffi', 'cryptography', 'rapidfuzz'
    ])
    print("✓ Dependencies installed\n")

    # Get paths
    script_dir = Path(__file__).parent.resolve()
    vault_script = script_dir / 'sofiavault.py'

    # Rename vault.py to sofiavault.py if needed
    old_script = script_dir / 'vault.py'
    if old_script.exists() and not vault_script.exists():
        old_script.rename(vault_script)

    bin_dir = get_bin_dir()

    # Create bin directory if needed
    bin_dir.mkdir(parents=True, exist_ok=True)

    if sys.platform == 'win32':
        # Windows: create a batch file wrapper
        bat_path = bin_dir / 'sofiavault.bat'
        with open(bat_path, 'w') as f:
            f.write(f'@echo off\npython "{vault_script}" %*\n')
        print(f"✓ Created {bat_path}")

        # Also create a PowerShell wrapper
        ps1_path = bin_dir / 'sofiavault.ps1'
        with open(ps1_path, 'w') as f:
            f.write(f'python "{vault_script}" @args\n')
        print(f"✓ Created {ps1_path}")

        # Check if bin_dir is in PATH
        path_env = os.environ.get('PATH', '')
        if str(bin_dir) not in path_env:
            print(f"\n⚠️  Add this to your PATH: {bin_dir}")
            print(f"   Or run: setx PATH \"%PATH%;{bin_dir}\"\n")
    else:
        # macOS/Linux: create a symlink or copy
        target = bin_dir / 'sofiavault'

        # Make script executable
        os.chmod(vault_script, 0o755)

        # Create symlink
        if target.exists() or target.is_symlink():
            target.unlink()
        target.symlink_to(vault_script)
        print(f"✓ Created symlink: {target} -> {vault_script}")

        # Check if bin_dir is in PATH
        path_env = os.environ.get('PATH', '')
        if str(bin_dir) not in path_env:
            shell = os.environ.get('SHELL', '')
            rc_file = '~/.zshrc' if 'zsh' in shell else '~/.bashrc'
            print(f"\n⚠️  Add this to your {rc_file}:")
            print('   export PATH="$HOME/.local/bin:$PATH"')
            print(f"   Then run: source {rc_file}\n")

    print("\n✅ Installation complete!")
    print("\nUsage:")
    print("  sofiavault add              Add new password")
    print("  sofiavault amazon           Get password (fuzzy match)")
    print("  sofiavault list             List all entries")
    print("  sofiavault delete amazon    Delete entry")
    print("  sofiavault import file.csv  Import from CSV")
    print("  sofiavault help             Show help\n")

if __name__ == '__main__':
    main()
