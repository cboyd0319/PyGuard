"""
RipGrep-based pre-filtering for PyGuard.

Fast pre-filtering using ripgrep to identify candidate files for AST analysis.
Dramatically improves performance for large codebases.
"""

import subprocess


class RipGrepFilter:
    """
    Fast pre-filtering using ripgrep to identify candidate files for AST analysis.
    """

    # High-risk patterns that warrant AST analysis
    SECURITY_PATTERNS = [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bcompile\s*\(",
        r"pickle\.loads",
        r"yaml\.load\s*\(",
        r"os\.system\s*\(",
        r"subprocess\..*shell\s*=\s*True",
        r'password\s*=\s*[\'"][^\'"]+[\'"]',
        r'api[_-]?key\s*=\s*[\'"][^\'"]+[\'"]',
        r"jwt\.decode\s*\(",
        r"render_template_string\s*\(",
        r"Crypto\.Cipher\.DES",
        r"hashlib\.(md5|sha1)\s*\(",
    ]

    @staticmethod
    def find_suspicious_files(path: str, patterns: list[str] | None = None) -> set[str]:
        """
        Use ripgrep to find Python files matching security patterns.

        Args:
            path: Directory or file path to scan
            patterns: Custom patterns (uses SECURITY_PATTERNS if None)

        Returns:
            Set of file paths that match patterns
        """
        if patterns is None:
            patterns = RipGrepFilter.SECURITY_PATTERNS

        # Build ripgrep pattern (OR all patterns)
        combined_pattern = "|".join(patterns)

        try:
            result = subprocess.run(
                [
                    "rg",
                    "--files-with-matches",
                    "--type",
                    "py",
                    "--ignore-case",
                    combined_pattern,
                    path,
                ],
                check=False, capture_output=True,
                text=True,
                timeout=60,
            )

            candidate_files = set(result.stdout.strip().split("\n"))
            candidate_files.discard("")  # Remove empty strings

            return candidate_files

        except subprocess.TimeoutExpired:
            print("Warning: RipGrep timeout - falling back to full scan")
            return set()
        except FileNotFoundError:
            # RipGrep not installed
            return set()

    @staticmethod
    def is_ripgrep_available() -> bool:
        """Check if ripgrep is installed."""
        try:
            subprocess.run(["rg", "--version"], check=False, capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
