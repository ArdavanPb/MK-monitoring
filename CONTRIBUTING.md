# Contributing to MikroTik Router Monitoring

Thank you for your interest in contributing to this project! This document provides guidelines and instructions for setting up and running the application from source.

## Quick Start

### Prerequisites
- Python 3.9+ or Docker
- Git

### Default Login Credentials
- **Username**: `admin`
- **Password**: `admin`

### Running from Git (Development Mode)

#### Option 1: Using Docker (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd mk-monitoring

# Start the application
docker-compose up -d

# Access the application at http://localhost:8080
```

#### Option 2: Manual Python Setup
```bash
# Clone the repository
git clone <repository-url>
cd mk-monitoring

# Run the setup script
./setup.sh

# Start the application
./run.sh

# Access the application at http://localhost:8080
```

## Development Setup

### 1. Fork and Clone
```bash
git clone https://github.com/your-username/mk-monitoring.git
cd mk-monitoring
```

### 2. Set Up Development Environment

#### Using Virtual Environment (Recommended)
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### Using Docker for Development
```bash
# Build and run with Docker
docker-compose up --build
```

### 3. Run the Application

#### Development Mode (Auto-reload)
```bash
# Using Python directly
python app.py

# Or using the provided script
./run.sh
```

#### Production Mode (Docker)
```bash
docker-compose up -d
```

## Project Structure

```
mk-monitoring/
├── app.py                    # Main Flask application
├── bandwidth_collector.py    # Background data collection
├── requirements.txt          # Python dependencies
├── templates/                # HTML templates
├── data/                     # Database directory (created automatically)
├── Dockerfile               # Docker container definition
├── docker-compose.yml       # Docker Compose configuration
├── setup.sh                 # Development setup script
├── run.sh                   # Development run script
└── README.md                # Project documentation
```

## Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and test them:
   ```bash
   # Test with Docker
   docker-compose up --build
   
   # Or test with Python
   ./run.sh
   ```

3. Commit your changes:
   ```bash
   git add .
   git commit -m "Description of your changes"
   ```

4. Push and create a pull request:
   ```bash
   git push origin feature/your-feature-name
   ```

## Troubleshooting

### Common Issues

#### Database Errors
If you encounter database errors, try:
```bash
# Rebuild Docker containers
docker-compose down
docker-compose build --no-cache
docker-compose up

# Or manually delete and recreate the database
rm -rf data/
mkdir data
```

#### Port Conflicts
If port 8080 is already in use:
```bash
# Change the port in docker-compose.yml
# Or run with a different port
python app.py --port 8081
```

### Getting Help
- Check the README.md for detailed documentation
- Review the troubleshooting guides in the docs/ directory
- Open an issue if you encounter bugs

## Code Style

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and single-purpose

## Testing

Before submitting changes, please:
- Test with both Docker and manual Python setup
- Verify the application starts without errors
- Test adding and monitoring routers
- Check that the bandwidth collector runs correctly

Thank you for contributing!