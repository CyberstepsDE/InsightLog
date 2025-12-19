# InsightLog

InsightLog is a Python script for extracting and analyzing data from server log files (Nginx, Apache2, and Auth logs). It provides tools to filter, parse, and analyze common server log formats.

## Features

- Filter log files by date, IP, or custom patterns
- Extract web requests and authentication attempts from logs
- Analyze logs from Nginx, Apache2, and system Auth logs

## Installation

Clone this repository:
```bash
git clone https://github.com/CyberstepsDE/insightlog.git
cd insightlog
```

You are ready to go!

## Command Line Usage

You can run the analyzer from the CLI:

```bash
python3 insightlog.py --service nginx --logfile logs-samples/nginx1.sample --filter 192.10.1.1
```

More examples:

- Analyze Apache2 logs for a specific IP:
  ```bash
  python3 insightlog.py --service apache2 --logfile logs-samples/apache1.sample --filter 127.0.1.1
  ```

- Analyze Auth logs for a specific string:
  ```bash
  python3 insightlog.py --service auth --logfile logs-samples/auth.sample --filter root
  ```

- Analyze all Nginx log entries (no filter):
  ```bash
  python3 insightlog.py --service nginx --logfile logs-samples/nginx1.sample
  ```

## Known Bugs

See [KNOWN_BUGS.md](KNOWN_BUGS.md) for a list of current bugs and how to replicate them.

## Planned Features

See [ROADMAP.md](ROADMAP.md) for planned features and improvements.

## Running Tests

We use Python's built-in `unittest` module for testing. To run the tests:

```bash
python3 -m unittest discover -s tests -v
```
### Recent Fixes

- Fixed IPv4 regex to prevent matching invalid IP addresses.
- Fixed regex filtering to match patterns anywhere in a log line (using `re.search`).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.