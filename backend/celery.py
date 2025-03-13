from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

# Establecer la configuración predeterminada de Django para Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

app = Celery('backend')

# Carga la configuración desde settings.py con el prefijo CELERY
app.config_from_object('django.conf:settings', namespace='CELERY')

# Descubrir tareas asíncronas en todos los archivos tasks.py
app.autodiscover_tasks()

# Configuración de tareas periódicas con Celery Beat
app.conf.beat_schedule = {
    'fetch-telemetry-every-10-minutes': {
        'task': 'telemetria.tasks.test_fetch_store_telemetry',
        'schedule': crontab(minute='*/10'),  # Cada 10 minutos
    },
    'update-ott-every-hour': {
        'task': 'telemetria.tasks.update_data_ott_task',
        'schedule': crontab(hour='*', minute=0),  # Cada hora en punto
    },
    'update-dvb-every-hour': {
        'task': 'telemetria.tasks.update_data_dvb_task',
        'schedule': crontab(hour='*', minute=15),  # Cada hora a los 15 minutos
    },
    'update-stop-catchup-every-day': {
        'task': 'telemetria.tasks.update_data_stop_catchup_task',
        'schedule': crontab(hour=0, minute=0),  # Medianoche diaria
    },
    'update-end-catchup-every-day': {
        'task': 'telemetria.tasks.update_data_end_catchup_task',
        'schedule': crontab(hour=0, minute=0),  # Medianoche diaria
    },
    'update-stop-vod-every-30-minutes': {
        'task': 'telemetria.tasks.update_data_stop_vod_task',
        'schedule': crontab(minute='*/30'),  # Cada 30 minutos
    },
    'update-end-vod-every-day': {
        'task': 'telemetria.tasks.update_data_end_vod_task',
        'schedule': crontab(hour=1, minute=0),  # 1:00 AM diaria
    },
}

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')  # Para depuración