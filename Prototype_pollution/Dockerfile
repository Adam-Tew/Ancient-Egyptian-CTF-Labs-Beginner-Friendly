FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
# Keep original port exposed internally
EXPOSE 5000
# Explicitly set the port via command line
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
