# Use a slim Python runtime as a parent image
FROM python:3.8-slim-buster

# Set environment variables
ENV MONGODB_URL=mongodb+srv://zeynepkrtls01:ZRAZ2x5rw9AXMllc@sugradcluster.aro7tnh.mongodb.net/

# Set the working directory in the container to /app
WORKDIR /app

# Copy the requirements.txt file into the container at /app
COPY ./requirements.txt /app/requirements.txt

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY ./ /app

# Make port 80 available to the world outside this container
EXPOSE 80

# Run the command to start uvicorn
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "80"]