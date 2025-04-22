#!/bin/bash

# Function to check and install missing dependencies
install_dependencies() {
    if ! command -v python3 &> /dev/null; then
        echo "Python3 is not installed. Installing Python3..."
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip
    fi

    if ! command -v pip3 &> /dev/null; then
        echo "pip3 is not installed. Installing pip3..."
        sudo apt-get install -y python3-pip
    fi

    # Install any necessary Python packages if required
    pip3 install -r requirements.txt
}

# Function to install the OpenVulnScan Agent
install_agent() {
    echo "Installing OpenVulnScan Agent..."

    # Define the directory where the agent will be installed
    AGENT_DIR="/opt/openvulnscan-agent"

    # Create the agent directory if it doesn't exist
    sudo mkdir -p $AGENT_DIR

    # Download the agent script from the server (replace with your actual URL)
    AGENT_URL="https://your-server.com/agent.py"
    sudo curl -o $AGENT_DIR/agent.py $AGENT_URL

    # Make the agent script executable
    sudo chmod +x $AGENT_DIR/agent.py

    # Optionally, set up cron jobs or systemd services for the agent to run periodically
    echo "OpenVulnScan Agent installed at $AGENT_DIR"
    
    #add Cron job
    echo "0 2 * * * python3 /opt/openvulnscan-agent/agent.py" | sudo tee -a /etc/crontab

}

# Function to check if the script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root or with sudo."
        exit 1
    fi
}

# Main script execution
check_root
install_dependencies
install_agent
