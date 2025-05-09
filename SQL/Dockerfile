FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
# Expose port 5000 (the port Flask actually uses by default)
EXPOSE 5000
# Run on port 5000 internally
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
