# MK-Monitoring Development Guide

## Build & Run Commands

### Docker (Recommended)
```bash
docker-compose up -d          # Start in background
docker-compose up --build     # Rebuild and start
docker-compose logs -f        # View logs
docker-compose down           # Stop
```

### Python Development
```bash
./setup.sh                    # Setup virtual env & dependencies
./run.sh                      # Run Flask app
python app.py                 # Run directly
python bandwidth_collector.py # Run background collector
```

### Database Management
```bash
python -c "from app import init_db; init_db()"  # Initialize/update DB
rm -rf data/ && mkdir data    # Reset database
```

## Code Style Guidelines

### Python Conventions
- **Imports**: Standard library first, then third-party, then local modules
- **Naming**: snake_case for variables/functions, PascalCase for classes
- **Error Handling**: Use try/except blocks with specific exceptions
- **Type Hints**: Add type annotations for function parameters and returns

### Flask Application Structure
- Use `@app.route()` decorators for route definitions
- Database connections: open/close in each request handler
- Session management: use Flask session for authentication
- Template rendering: use `render_template()` with context

### Database Schema
- SQLite database at `/app/data/routers.db` (Docker) or `data/routers.db` (local)
- Tables: `routers`, `ip_bandwidth_data`, `router_status_cache`, `users`
- Use parameterized queries to prevent SQL injection

### RouterOS API Integration
- Use `routeros-api` library for MikroTik connections
- Handle connection timeouts and authentication errors gracefully
- Cache router status to reduce API calls
- Collect bandwidth data via background scheduler

### File Organization
- Main app logic in `app.py`
- Background tasks in `bandwidth_collector.py`
- Templates in `templates/` directory
- Database in `data/` directory

### Error Handling Patterns
```python
try:
    api, connection, error = connect_to_router(host, port, username, password)
    if api:
        # Process data
        connection.disconnect()
    else:
        flash(f'Connection failed: {error}', 'error')
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Security Practices
- Hash passwords with SHA-256
- Use Flask sessions for authentication
- Validate all user inputs
- Use parameterized SQL queries
- Store sensitive data in environment variables

### Testing Approach
- Manual testing with actual MikroTik routers
- Verify database operations work correctly
- Test both Docker and Python environments
- Check bandwidth collector runs without errors