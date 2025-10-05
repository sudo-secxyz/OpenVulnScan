FROM ubuntu

# Install nmap and Python
RUN pip3 uninstall -y bcrypt py-bcrypt || true
RUN rm -rf /root/.cache/pip
RUN apt-get update && apt-get install -y systemd nmap python3 python3-pip whatweb && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y build-essential libffi-dev python3-dev

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Copy app files
COPY . .

# Create necessary dirs
RUN mkdir -p data templates static
RUN mkdir -p /app/data
# Create log directory with appropriate permissions
RUN mkdir -p /var/log && chmod 777 /var/log
RUN chmod -R 777 /app
ENV PYTHONPATH=/app

# Expose port and run app
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]