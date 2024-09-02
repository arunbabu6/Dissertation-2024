# Use the official Nginx image as the base image
FROM nginx:alpine

# Install git and curl to clone the repository and make HTTP requests
RUN apk add --no-cache git curl

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
