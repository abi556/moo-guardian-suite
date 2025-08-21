## Usage

Scan a directory (detect only):
```bash
python guardian.py scan "."
```

Scan and quarantine detections:
```bash
python guardian.py scan "." --quarantine --quarantine-dir "~/quarantine"
```

Decrypt a single file in-place:
```bash
python guardian.py decrypt-file path/to/file
```

Decrypt all files under a directory in-place (CAUTION: only use on test dirs):
```bash
python guardian.py decrypt-dir path/to/dir
```
