# eBPF Security Monitoring Tool

This project is an advanced security monitoring tool that leverages eBPF (extended Berkeley Packet Filter) technology to provide real-time system activity monitoring and threat detection.

## Features

- Real-time monitoring of various system activities:
  - Process launches
  - File accesses
  - Kernel module loads
  - eBPF program loads
  - LD_PRELOAD usage
  - Syscalls
  - Executions from specific mounts
  - Hardlink and symlink creations
  - Capability usage
  - Environment variable reads
  - Network domain requests

- Two operational modes:
  1. Learning mode: Builds a baseline of normal system behavior
  2. Alert/Block mode: Detects and reports (or optionally blocks) anomalous activities

- Configurable rules engine for fine-tuned security policies
- Asynchronous event processing for improved performance

## Requirements

- Linux kernel 4.15+ (for full eBPF support)
- Python 3.7+
- BCC (BPF Compiler Collection)

## Installation

1. Install the required packages:

```
pip install -r requirements.txt
```

2. Ensure you have the necessary permissions to run eBPF programs (typically root access is required).

## Usage

To run the tool in learning mode:

```
sudo python src/main.py --learning --verbose
```

To run the tool in alert/block mode:

```
sudo python src/main.py --alert --verbose
```

## Configuration

The tool uses a YAML configuration file (`config.yaml`) to store rules and settings. You can modify this file to adjust the tool's behavior according to your security needs.

## Project Structure

- `src/`: Contains the main Python source code
  - `main.py`: Entry point of the application
  - `monitor.py`: Core monitoring logic
  - `bpf_manager.py`: Manages eBPF program loading and event handling
  - `rule_engine.py`: Implements the security rules logic
  - `config_manager.py`: Handles configuration loading and saving

- `ebpf_programs/`: Contains eBPF program sources written in C
  - Separate `.c` files for each monitored event type

## Extending the Tool

To add new monitoring capabilities:

1. Create a new eBPF program in the `ebpf_programs/` directory.
2. Add a corresponding handler in `bpf_manager.py`.
3. Update the `RuleEngine` class in `rule_engine.py` to process the new event type.
4. Modify the `Monitor` class in `monitor.py` to include the new event in the processing loop.

## Contributing

Contributions are welcome! I know its messy, but I'm just getting started. Please feel free to submit a Pull Request.

## License

This project is open-source and available under the Mozilla Public License.

## Disclaimer

This tool provides monitoring capabilities that may be considered intrusive. Ensure you have the necessary permissions and comply with all relevant policies and regulations when using this tool in any environment.
