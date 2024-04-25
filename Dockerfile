FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY slackotp.py .
COPY gunicorn.conf.py .

# Set a default port in case $PORT isn't provided
ENV PORT 8000

# Expose the port defined in $PORT, default is 8000
EXPOSE $PORT

# Start Gunicorn with the configuration file
CMD gunicorn --config gunicorn.conf.py slackotp:app