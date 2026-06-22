# smbthief

SMB share enumerator using Impacket. Reads a `socks.txt`-style target list, connects with null sessions (or creds via env vars), lists shares, verifies read access, dedupes results, and prints accessible shares.

## Requirements

```
pip install impacket colorama
```

`colorama` is optional — only used for colored output.

## Usage

```
python smbthief.py [infile] [-j JOBS] [-v] [-d]
```

| Argument | Default | Description |
|---|---|---|
| `infile` | `socks.txt` | Target list (see format below) |
| `-j`, `--jobs` | `min(32, 4*cpu)` | Concurrent workers |
| `-v`, `--verbose` | off | Print progress per target to stderr |
| `-d`, `--debug` | off | Verbose debug output to stderr |
| `-P`, `--proxychains-conf` | none | Print a `proxychains4` connect command using this conf file |

## Input format

Standard `socks.txt` format (e.g. from CrackMapExec or Metasploit):

```
SMB 192.168.1.10 DOMAIN/username
SMB 192.168.1.11 WORKGROUP/Administrator
SMB 192.168.1.12 username
```

Columns: `SMB <ip> <domain/user>`. Lines not starting with `SMB` are skipped.

## Credential overrides

Override credentials globally via env vars (applies to all targets):

```bash
SMB_USER=Administrator python smbthief.py           # null password, custom user
SMB_DOMAIN=CORP SMB_USER=jsmith python smbthief.py  # domain + user
```

When `SMB_USER` is set, one connection attempt per unique IP (ignores per-line user).

## Proxychains

Run enumeration through a SOCKS proxy:

```bash
proxychains python smbthief.py socks.txt
```

Pass `-P` to also print a ready-to-run `impacket-smbclient` connect command under each result:

```bash
python smbthief.py -P ../proxychains4.conf socks.txt
```

Output per host:

```
  192.168.1.10  (DOMAIN/username)
  --------------------------------------------------
  [*] Backups
  [*] Data

  proxychains4 -q -f ../proxychains4.conf impacket-smbclient -no-pass DOMAIN/username@192.168.1.10
```

## Output

Only hosts with at least one readable non-admin share are printed. Results are deduped by `(ip, share-set)` to suppress duplicates from the target list.

```
  192.168.1.10  (DOMAIN/username)
  --------------------------------------------------
  [*] Backups
  [*] Data
  [*] IT
```

Admin shares (`C$`, `ADMIN$`, `IPC$`) are always excluded.

## Notes

- Connects on port 445 with a 15-second timeout
- Null session = empty password
- Accessibility verified by listing the share root (`listPath`)
