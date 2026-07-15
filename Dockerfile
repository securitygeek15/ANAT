FROM python:3.10-slim

WORKDIR /app

# Install system dependencies required for scapy/network sniffing
RUN apt-get update && apt-get install -y \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose Flask port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
