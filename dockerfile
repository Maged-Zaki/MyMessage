# Use the official Python base image
FROM python:3.11.5

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

# Install any needed dependencies specified in macOs_requirements.txt # difference between this and windows_requirements.txt is macOs_requirements.txt have windows specfic liberaries excluded
RUN pip install -r macOs_requirements.txt


# Expose the port the app runs on
EXPOSE 5000

# Run the Flask application
CMD ["flask", "run"]
