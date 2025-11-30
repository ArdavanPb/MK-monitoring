# MK-Monitoring Project Commands

## Development Commands
- **Run application**: `python app.py`
- **Check syntax**: `python -m py_compile app.py`
- **Start with Docker**: `docker-compose up`

## Template Field Names for Connections
When processing firewall connections in app.py, use these EXACT field names:
```python
processed_conn = {
    'src_ip': src_ip,                    # Source IP address
    'src_hostname': hostname or '-',     # Source hostname
    'dst_ip': dst_ip,                    # Destination IP address  
    'dst_hostname': sni or dst_ip,       # Destination hostname/domain
    'service': service_name,             # Service name (HTTPS, YouTube, DNS, etc.)
    'upload_bytes': sent_bytes,          # Raw upload bytes (int)
    'download_bytes': received,          # Raw download bytes (int)
    'upload_human': format_bytes(sent_bytes),    # Formatted upload
    'download_human': format_bytes(received),    # Formatted download
    'duration': format_duration(timeout),        # Connection duration
    'protocol': protocol                 # Protocol (TCP/UDP)
}
```

## Code Style Preferences
- Use consistent field naming across all connection processing functions
- Always include both raw bytes and human-readable formatted values
- Template should use `upload_bytes` and `download_bytes` for calculations
- Template should use `upload_human` and `download_human` for display

## Important Notes
- The connections.html template expects these exact field names
- Never use old field names like `src_address`, `dst_address`, `dst_domain`
- The grouped connections view uses `upload_bytes` and `download_bytes` for sum calculations