# Port Scanner — examples

These commands illustrate common ways to use the scanner. Replace the host
with one you own or have explicit permission to scan. **Authorized use only.**

## Scan your own loopback, top 100 ports

```bash
python port_scanner.py 127.0.0.1 --top-ports 100
```

## Scan a range on a host you control

```bash
python port_scanner.py 192.168.1.10 --ports 1-1024 --concurrency 128 --timeout 1.0
```

## Grab banners to confirm the running service

```bash
python port_scanner.py db.internal --ports 22,3306,5432 --banner
```

## Only open ports, one per line (easy to pipe)

```bash
python port_scanner.py web.example --top-ports 100 --just-important
# 22	open	ssh	SAFE
# 80	open	http	WARN
# 443	open	https	SAFE
```

## Machine-readable JSON

```bash
python port_scanner.py web.example --top-ports 50 --json --no-color
```

## Quiet mode (scripting): exit code == 1 when risky found

```bash
python port_scanner.py 127.0.0.1 --top-ports 100 --quiet
echo $?   # 0 = clean, 1 = risky service found, 2 = usage error
```
