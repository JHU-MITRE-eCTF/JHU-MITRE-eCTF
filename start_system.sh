#!/bin/bash

# Automatically detect the project root directory
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Define required variables
SECRETS_FILE="$PROJECT_ROOT/secrets/secrets.json"
FRAME_FILE="$PROJECT_ROOT/frames/x_c0.json"
UPLINK_PORT=2000
SATELLITE_PORT=2001
DECODER_PORT="/dev/tty.usbmodem1113102"

# Function to launch a command in a new macOS Terminal window
launch_terminal() {
    osascript -e "tell application \"Terminal\" to do script \"cd $PROJECT_ROOT && source ./.venv/bin/activate && $1\""
}

echo "Starting eCTF System..."

# Step 1: Start Uplink
echo "Launching Uplink..."
cd "$PROJECT_ROOT"
source ./.venv/bin/activate
python -m ectf25.uplink "$SECRETS_FILE" localhost "$UPLINK_PORT" 1:10:"$FRAME_FILE" &
sleep 2  # Ensure uplink is fully running before proceeding

# Step 2: Start Satellite in a new terminal
echo "Launching Satellite..."
launch_terminal "python -m ectf25.satellite localhost $UPLINK_PORT localhost 1:$SATELLITE_PORT"
sleep 2  # Allow satellite to initialize

# Step 3: Start TV in a new terminal
echo "Launching TV..."
launch_terminal "python -m ectf25.tv.run localhost $SATELLITE_PORT $DECODER_PORT"

echo "All components started successfully!"
