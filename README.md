# SMB ACL Scanner

Python package for reading Windows ACLs (Access Control Lists) from NTFS filesystems via SMB protocol with LDAP name resolution.

## Features

- Read Windows ACLs via SMB2/SMB3 protocol
- Recursive directory scanning
- LDAP integration for SID-to-name resolution
- Export to CSV, JSON formats
- Search for user/group permissions
- Command-line interface

## Installation

### From PyPI (when published)
```bash
pip install smb-acl-scanner
```

### From source
```bash
git clone https://github.com/yourusername/smb-acl-scanner.git
cd smb-acl-scanner
pip install -e .
```

## Usage

### As a Library

```python
from smb_acl_scanner import SMBACLReader, LDAPResolver

# Initialize
acl_reader = SMBACLReader("username", "password", "DOMAIN")
ldap_resolver = LDAPResolver("ldap.example.com", "ldap_user", "ldap_pass", "example.com")
ldap_resolver.connect()

# Scan directory
for item in acl_reader.scan_directory(r'\\\\server\\share\\folder', recursive=True):
    if 'security' in item:
        owner = ldap_resolver.resolve_sid(item['security']['owner'])
        print(f"{item['path']}: Owner = {owner}")

ldap_resolver.disconnect()
```

### Command-line Interface

```bash
# Scan a directory
smb-acl-scan \\\\server\\share\\folder -u username -p password -d DOMAIN

# Export to CSV
smb-acl-scan \\\\server\\share\\folder -u username -p password -d DOMAIN --output acls.csv

# With LDAP resolution
smb-acl-scan \\\\server\\share\\folder -u username -p password -d DOMAIN \\
    --ldap-server ldap.example.com --ldap-user admin --ldap-password pass \\
    --ldap-domain example.com

# Limit depth
smb-acl-scan \\\\server\\share\\folder -u username -p password -d DOMAIN --max-depth 2
```

## Advanced Usage

### Export to JSON
```python
from smb_acl_scanner.utils import export_acls_to_json

export_acls_to_json(acl_reader, ldap_resolver, r'\\\\server\\share', 'output.json')
```

### Find paths with specific user
```python
from smb_acl_scanner.utils import find_paths_with_user

paths = find_paths_with_user(
    acl_reader, 
    ldap_resolver, 
    r'\\\\server\\share', 
    'DOMAIN\\username'
)

for path_info in paths:
    print(f"{path_info['path']}: {path_info['permissions']}")
```

## Requirements

- Python 3.8+
- smbprotocol >= 1.14.0
- ldap3 >= 2.9.1

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.