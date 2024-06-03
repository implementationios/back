## elnazar la base de datos para el admin para poder ver los elemetos en la base de datos desde django/admin
from django.contrib import admin
from .models import Telemetria
admin.site.register(Telemetria)