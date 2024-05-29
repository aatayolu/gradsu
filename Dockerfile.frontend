# Use an official Nginx runtime as a parent image
FROM nginx:1.21

# Remove the default Nginx configuration file
RUN rm /etc/nginx/conf.d/default.conf

# Add a new Nginx configuration file
COPY nginx.conf /etc/nginx/conf.d

# Copy the frontend directory contents into the container at /usr/share/nginx/html
COPY ./frontend/ /usr/share/nginx/html

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Start Nginx when the container launches
CMD ["nginx", "-g", "daemon off;"]