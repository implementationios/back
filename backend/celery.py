from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Establecer la configuración predeterminada de Django para Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

app = Celery('backend')

# Usar una cadena aquí significa que los trabajadores no tendrán que
# volver a importar la configuración del módulo del objeto.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Descubrir tareas asíncronas en todos los archivos tasks.py
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
