FROM nginx:latest

# Kopiujemy config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Kopiujemy certyfikaty
COPY cert.pem /etc/nginx/ssl/cert.pem
COPY key.pem /etc/nginx/ssl/key.pem

# ZMIANY DLA NON-ROOT:
# 1. Musimy zmienić właściciela certyfikatów na użytkownika 'nginx', żeby mógł je czytać
RUN chown -R nginx:nginx /etc/nginx/ssl

# 2. Nginx musi móc pisać do swoich folderów tymczasowych jako zwykły user
RUN chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

# 3. Przełączamy się na użytkownika 'nginx' (UID 101)
USER nginx

# Teraz kontener startuje już bez uprawnień roota!