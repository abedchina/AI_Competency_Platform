# Loaded automatically by gunicorn from the working directory.
# Threads let many students chat at once while one request waits for Gemini.
worker_class = "gthread"
workers = 1          # one process keeps the SQLite file consistent; Postgres can use more
threads = 8
timeout = 120
