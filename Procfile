web: gunicorn backend.wsgi --log-file -
worker: celery -A backend worker --loglevel=info
beat: celery -A backend beat --loglevel=info