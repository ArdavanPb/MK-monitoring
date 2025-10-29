# MikroTik Router Monitoring Application

A Flask web application that connects to MikroTik routers via API to monitor and display router information including uptime, memory usage, CPU load, and more.

## Features

- **Secure Credential Storage**: Router credentials are stored securely in a local SQLite database
- **Multiple Router Support**: Monitor multiple MikroTik routers from a single dashboard
- **Real-time Monitoring**: View router name, uptime, memory usage, CPU load, and firmware version
- **Detailed Monitoring**: Comprehensive system information including IP addresses, system identity, clock, and health data
- **Connection Testing**: Test router connections before adding them to the system
- **Custom API Port**: Support for custom MikroTik API ports (default: 8728)
- **Router Management**: Add, refresh, and delete routers from the dashboard
- **Responsive Design**: Bootstrap-based responsive interface

## Installation

### Docker (Recommended)

1. Clone or download this repository
2. Build and run with Docker Compose:
   ```bash
   docker-compose up -d
   ```
3. Open your browser and navigate to `http://localhost:8080`

### Manual Installation

1. Clone or download this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### Router API Setup

Before using this application, ensure your MikroTik router has API access enabled:

1. Log into your MikroTik router via WinBox or WebFig
2. Go to **System > Users**
3. Create a new user or edit an existing one
4. Enable **API** and **Read** permissions (at minimum)
5. For enhanced security, consider creating a dedicated API user

### Application Setup

#### Docker Method
1. Run the application:
   ```bash
   docker-compose up -d
   ```
2. Open your browser and navigate to `http://localhost:8080`

#### Manual Method
1. Run the application:
   ```bash
   python app.py
   ```
2. Open your browser and navigate to `http://localhost:8080`

3. Click "Add Router" to add your first MikroTik router

## Usage

1. **Add Router**: Click "Add Router" and provide:
   - Display name (for your reference)
   - Router IP/hostname
   - API username
   - API password

2. **View Dashboard**: The main dashboard shows all configured routers with:
   - Router name and identity
   - Uptime
   - Memory usage with visual progress bar
   - CPU load with color-coded status
   - Firmware version

3. **Manage Routers**: 
   - Refresh individual router data
   - Delete routers you no longer want to monitor

## Security Notes

- Credentials are stored in a local SQLite database
- The application uses plaintext API authentication (required by MikroTik API)
- Consider running this application on a secure internal network
- Use dedicated API users with minimal required permissions

## API Information Retrieved

- System identity (router name)
- System resources (memory, CPU)
- Uptime
- Firmware version

## Dependencies

- **Flask**: Web framework
- **routeros-api**: Python library for MikroTik RouterOS API

## File Structure

```
mk-monitoring/
├── app.py              # Main Flask application
├── routers.db          # SQLite database (created automatically)
├── requirements.txt    # Python dependencies
├── templates/          # HTML templates
│   ├── base.html
│   ├── index.html
│   └── add_router.html
├── Dockerfile          # Docker container definition
├── docker-compose.yml  # Docker Compose configuration
├── .dockerignore       # Docker ignore patterns
├── setup.sh           # Manual setup script
├── run.sh             # Manual run script
└── README.md
```

## Docker Commands

- **Start**: `docker-compose up -d`
- **Stop**: `docker-compose down`
- **View logs**: `docker-compose logs -f`
- **Rebuild**: `docker-compose up -d --build`
- **Check status**: `docker-compose ps`

## Database Storage

The application uses SQLite database stored in `/tmp/routers.db` within the container. Note that data will be lost when the container is removed. For persistent storage, you can modify the docker-compose.yml to mount a volume.