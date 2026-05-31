# Password Cracker Automation Tool

A command-line password hash cracking tool using dictionary wordlists and transformation rules.

## What it does
- Accepts a single hash or a file containing many hashes.
- Supports common hash algorithms: `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha3_256`, and `ntlm`.
- Loads built-in `.txt` wordlists from `wordlists/` and additional user-supplied wordlists.
- Applies candidate transformations like case variants, reverse, leetspeak, and numeric suffixes.
- Optional brute-force generation for short passwords.

## Important
> Use this only on hashes you own or have explicit permission to test.

## Run it
```bash
cd /home/krzx-mythoz/projects/PASSGUARD-X
python3 cracker.py --gui
```

If Tkinter is unavailable, PASSGUARD-X will automatically launch a browser-based web UI instead.

To run the web app directly, use:
```bash
python3 cracker.py
```

## Example CLI usage
```bash
python3 cracker.py --hash-file hashes.txt --wordlist custom.txt --threads 4
```

## Wordlists
- The tool automatically loads all `.txt` files in the `wordlists/` directory.
- Add your own `.txt` wordlist files to `wordlists/` or pass paths with `--wordlist`.
- Use `--no-builtin` to disable the built-in sample lists.

## Notes
- This is a practical dictionary-based hash cracker. It is not a full network or protocol cracker like Hydra.
- For best results, use large wordlists and tune `--bruteforce-length` only for very short passwords.
