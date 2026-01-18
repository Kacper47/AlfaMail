FROM python:3.11-slim

WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Start the Uvicorn server on port 8000 
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]