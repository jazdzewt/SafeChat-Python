FROM python:3.11-slim

WORKDIR /app

# Instalacja zależności systemowych (potrzebne dla kryptografii)
RUN apt-get update && apt-get install -y gcc libffi-dev musl-dev && rm -rf /var/lib/apt/lists/*

# Instalacja bibliotek Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiowanie kodu aplikacji
COPY . .

# Uruchomienie serwera produkcyjnego Gunicorn
# 4 workery pozwolą obsłużyć kilka zapytań naraz
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]