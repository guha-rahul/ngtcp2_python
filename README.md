# ngtcp2-python

Python bindings for the [ngtcp2](https://github.com/ngtcp2/ngtcp2) QUIC library.

## Overview

ngtcp2-python provides Python bindings for ngtcp2, a high-performance QUIC library written in C. This package allows you to use ngtcp2's functionality directly from Python applications.

## Requirements

- Python 3.8+
- ngtcp2 library (C library)
- CFFI

## Installation

### Prerequisites

First, you need to install the ngtcp2 C library. You can either:

1. **Install from source:**
   ```bash
   git clone https://github.com/ngtcp2/ngtcp2.git
   cd ngtcp2
   mkdir build && cd build
   cmake ..
   make
   make install
   ```

2. **Install via package manager:**
   ```bash
   # On macOS with Homebrew
   brew install ngtcp2
   
   # On Ubuntu/Debian
   sudo apt-get install libngtcp2-dev
   ```

### Install ngtcp2-python

```bash
# Development installation
git clone <your-repo-url>
cd ngtcp2-python
pip install -e .

# Or install from PyPI (when published)
pip install ngtcp2-python
```

## Quick Start

```python
import ngtcp2_python

# Get ngtcp2 version information
version_info = ngtcp2_python.get_version_info()
print(f"ngtcp2 version: {version_info['version_str']}")

# Create an ngtcp2 FFI instance
ngtcp2 = ngtcp2_python.NGTCP2FFI()

# Create connection IDs
cid1 = ngtcp2.create_cid(b"hello")
cid2 = ngtcp2.create_cid(b"world")

# Compare connection IDs
are_equal = ngtcp2.compare_cids(cid1, cid2)
print(f"CIDs are equal: {are_equal}")
```

## Building from Source

If you have ngtcp2 installed in a custom location, you can specify the paths:

```bash
export NGTCP2_INCLUDE_DIR=/path/to/ngtcp2/include
export NGTCP2_LIB_DIR=/path/to/ngtcp2/lib
python -m ngtcp2_python._build_ffi
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/

# Format code
black ngtcp2_python/

# Type checking
mypy ngtcp2_python/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [ngtcp2](https://github.com/ngtcp2/ngtcp2) - The underlying QUIC library
- [CFFI](https://cffi.readthedocs.io/) - C Foreign Function Interface for Python 