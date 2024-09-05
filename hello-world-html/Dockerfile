FROM nginx:alpine

# Install git and curl to clone the repository and make HTTP requests
RUN apk add --no-cache git curl

# Create all potential Nginx cache directories and set permissions
RUN mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp /var/cache/nginx/fastcgi_temp \
    /var/cache/nginx/uwsgi_temp /var/cache/nginx/scgi_temp && \
    chown -R nginx:nginx /var/cache/nginx

# Set the working directory
WORKDIR /usr/share/nginx/html

# Remove the default Nginx HTML files
RUN rm -rf ./*

# Clone the repository into the working directory
RUN git clone https://github.com/ithinkihaveacat/hello-world-html.git .

# Clean up unnecessary files like the .git directory
RUN rm -rf .git

# Expose port 80
EXPOSE 80

# Start a script that runs both Nginx and the curl command
ENTRYPOINT sh -c "nginx -g 'daemon off;' & while true; do curl -s https://www.google.com; sleep 10; done"
