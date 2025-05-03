# Use an official Python runtime as a parent image
# Using a specific version and the 'slim' variant is recommended for smaller size
FROM python:3.10-slim-bullseye

# Set environment variables
# Ensures Python output is sent straight to the terminal without buffering
ENV PYTHONUNBUFFERED=1
# Set default monitored email (can be overridden at runtime) - Optional
# ENV MONITORED_EMAIL="admin@mausamrai.com.np"

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt ./

# Install any needed packages specified in requirements.txt
# --no-cache-dir reduces image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code (your python script, credentials.json)
# into the working directory (/app)
# Make sure your Python script is named correctly here (e.g., email_monitor.py)
# IMPORTANT: This copies credentials.json into the image. See notes below for alternatives.
COPY ./Phising_Mail_Detection/final_script.py .
COPY ./Phising_Mail_Detection/credentials.json .
COPY ./.env .
COPY ./Phising_Mail_Detection/token.json .
# If you have other local files needed by the script, COPY them too.

# Command to run the application when the container launches
# Replace 'your_script_name.py' with the actual filename of your Python script
CMD ["python", "./final_script.py"]