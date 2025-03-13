## elnazar la base de datos para el admin para poder ver los elemetos en la base de datos desde django/admin
from django.contrib import admin
from .models import Telemetria, MergedTelemetricOTT, MergedTelemetricDVB, MergedTelemetricStopCatchup, MergedTelemetricEndCatchup, MergedTelemetricStopVOD, MergedTelemetricEndVOD

admin.site.register(Telemetria)
admin.site.register(MergedTelemetricOTT)
admin.site.register(MergedTelemetricDVB)
admin.site.register(MergedTelemetricStopCatchup)
admin.site.register(MergedTelemetricEndCatchup)
admin.site.register(MergedTelemetricStopVOD)
admin.site.register(MergedTelemetricEndVOD)
