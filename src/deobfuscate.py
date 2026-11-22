"""
deobfuscate.py

Attackers rewrite PowerShell so it does the same thing but no longer matches
simple text rules. Before scoring a command we normalize it back toward its
plain form so a pattern like "downloadstring" can match again.

This covers the three tricks from the workshop notes:
  1. base64 -EncodedCommand (-enc)
  2. string concatenation: 'I'+'EX'
  3. backtick escapes: New-Ob`ject
plus a [char] array decoder as a bonus.

Standard library only, so it runs anywhere with `python3`.
"""

import base64
import re

# Matches  -e / -enc / -encodedcommand  followed by a long base64 blob.
# Group 3 is the base64 string itself.
_ENC = re.compile(r"-e(nc(odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)

# Matches a run of single-quoted pieces joined by + , e.g.  'I'+'E'+'X'
_CONCAT = re.compile(r"(?:'[^']*'\s*\+\s*)+'[^']*'")

# Matches  [char[]](73,69,88)  or  [char]73  style sequences
_CHARARR = re.compile(r"\[char\[?\]?\]\s*\(?\s*([0-9,\s]+)\)?", re.IGNORECASE)


def decode_encoded_command(cmd: str) -> str:
    """If the command uses -enc <base64>, return the decoded inner command.
    PowerShell base64 is UTF-16LE text, which is why decoded bytes have
    alternating null characters that we strip with utf-16-le."""
    m = _ENC.search(cmd)
    if not m:
        return cmd
    try:
        raw = base64.b64decode(m.group(3))
        return raw.decode("utf-16-le", errors="ignore")
    except Exception:
        # If it is not valid base64, leave the command unchanged.
        return cmd


def _strip_backticks(cmd: str) -> str:
    """Remove backticks used as escape characters (New-Ob`ject -> New-Object).
    A backtick before a normal letter means nothing to PowerShell, so dropping
    it reveals the real token."""
    return cmd.replace("`", "")


def _join_concats(cmd: str) -> str:
    """Collapse 'I'+'E'+'X' into IEX by removing the quotes and plus signs."""
    def repl(match: re.Match) -> str:
        pieces = re.findall(r"'([^']*)'", match.group(0))
        return "".join(pieces)
    return _CONCAT.sub(repl, cmd)


def _join_char_arrays(cmd: str) -> str:
    """Turn [char[]](73,69,88) into the string IEX."""
    def repl(match: re.Match) -> str:
        nums = [n for n in re.findall(r"\d+", match.group(1))]
        try:
            return "".join(chr(int(n)) for n in nums)
        except ValueError:
            return match.group(0)
    return _CHARARR.sub(repl, cmd)


def normalize(cmd: str) -> str:
    """Run every de-obfuscation pass and lowercase the result.
    The output is meant for pattern matching, not for re-execution."""
    cmd = decode_encoded_command(cmd)
    cmd = _strip_backticks(cmd)
    cmd = _join_concats(cmd)
    cmd = _join_char_arrays(cmd)
    return cmd.lower()


if __name__ == "__main__":
    # Quick manual check. The base64 below decodes to a harmless command.
    samples = [
        "New-Ob`ject Net.WebClient",
        "& ('I'+'E'+'X') $code",
        "& (-join [char[]](73,69,88)) $payload",
        "powershell -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGgAaQAnAA==",
    ]
    for s in samples:
        print(f"{s}\n  -> {normalize(s)}\n")
