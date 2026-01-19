FROM python:3.11-slim

WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# sqlite
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

# Copy the rest of the application code
COPY . .

# Start the Uvicorn server on port 8000 
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]