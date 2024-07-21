from django.urls import path
from .views import TestFetchAndStoreTelemetry, MergeData, UpdateDataEndCatchup, UpdateDataEndVOD, UpdateDataOTT, UpdateDataDVB, TelemetriaHome, UpdateDataStopCatchup, UpdateDataStopVOD

# Definir las URL para las vistas de Django
urlpatterns = [
    # Ruta para probar la obtención y almacenamiento de datos de telemetría
    path('test/', TestFetchAndStoreTelemetry.as_view(), name='test'),
    
    # Rutas para actualizar diferentes tablas (OTT, DVB, etc.)
    path('ott/', UpdateDataOTT.as_view()),  # Actualiza la tabla ott
    path('dvb/', UpdateDataDVB.as_view()),  # Actualiza la tabla dvb
    path('stopcatchup/', UpdateDataStopCatchup.as_view()),  # Actualiza la tabla stopcatchup
    path('endcatchup/', UpdateDataEndCatchup.as_view()),  # Actualiza la tabla endcatchup
    path('stopvod/', UpdateDataStopVOD.as_view()),  # Actualiza la tabla stopvod
    path('endvod/', UpdateDataEndVOD.as_view()),  # Actualiza la tabla endvod
    
    # Ruta para mostrar datos en la vista de inicio (home)
    path('home/<int:days>/', TelemetriaHome.as_view()),  # Vista de datos en home
]