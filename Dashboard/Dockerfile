# Use an official Python runtime as a parent image
FROM python:3.9-slim AS base

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# --- Dependencies ---
# Copy the requirements file FROM THE BUILD CONTEXT (which will be project_root)
# Note: The source path 'requirements.txt' is relative to the build context, NOT the Dockerfile location.
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# --- Application Code ---
# Copy the application code FROM THE BUILD CONTEXT into the container
# Copies the contents of 'app_directory' from the host into '/app' in the container
COPY ./Dashboard/ .

# --- Runtime ---
# Make port 5000 available to the world outside this container (or your Flask app's port)
EXPOSE 5000

# Define the command to run your app using Flask development server
# Use --host=0.0.0.0 to make it accessible from outside the container
# Replace 'app:app' with 'your_main_script_name:your_flask_app_instance_name' if different
#CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]

# Or if you run using `python app.py`:
CMD ["python", "app.py"]