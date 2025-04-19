# OpenVulnScan

A simple vulnerability scanning application built with FastAPI.

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   uvicorn app:app --reload
   ```

3. Access the web interface at http://localhost:8000

## Features

- Run vulnerability scans against specified targets
- View scan history and results
- Generate PDF reports of scan findings

## Project Structure

- `app.py`: Main application entry point
- `config.py`: Configuration settings
- `database/`: Database operations
- `models/`: Pydantic models
- `scanners/`: Scanner implementations
- `services/`: Business logic services
- `utils/`: Utility functions
- `templates/`: HTML templates
- `static/`: Static files
- `data/`: Data storage

## License

MIT