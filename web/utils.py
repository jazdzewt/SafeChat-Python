import os 

def get_secret(secret_name):
    # 1. Najpierw próbujemy Docker Secrets (plik)
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as file:
            return file.read().strip()
    except IOError:
        # 2. Jak nie ma pliku, szukamy w zmiennych (dla kompatybilności)
        key = os.environ.get(secret_name.upper())
        if key:
            return key
            
    # 3. Jeśli nigdzie nie ma klucza - STOP! Nie uruchamiaj aplikacji
    raise ValueError(f"CRITICAL ERROR: No Secret '{secret_name}'!")