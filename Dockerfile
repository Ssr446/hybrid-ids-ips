# Use official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Ensure simulation.pcap is generated if it doesn't exist
RUN python generate_pcap.py

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Default to simulation mode for Docker deployment
ENV SIMULATION_MODE=true

# Run app.py when the container launches using gunicorn
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5000", "app:app"]
