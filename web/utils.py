import os 
from werkzeug.utils import secure_filename

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


FORBIDDEN_EXTENSIONS = {
    'exe', 'bat', 'com', 'cmd', 'sh', 'vbs', 'ps1', 'jar', 'msi', 'php', 'py', 'pl'
}

def validate_file(file_storage):
    filename = secure_filename(file_storage.filename)
    if not filename:
        return None
        
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in FORBIDDEN_EXTENSIONS:
        return False
    return filename