from django.urls import path
from .views import   DataTelemetria,MergeData, UpdateDataEndCatchup, UpdateDataEndVOD ,UpdateDataOTT,UpdateDataDVB,TelemetriaHome, UpdateDataStopCatchup, UpdateDataStopVOD

# Definir las URL para las vistas de Django
urlpatterns = [
    path("dataTelemetria/", MergeData.as_view()),  # Vista para manejar datos de telemetría
    path('ott/', UpdateDataOTT.as_view()), #actualiza la tabla ott
    path('dvb/', UpdateDataDVB.as_view()), #actualiza la tabla dvb
    path('stopcatchup/', UpdateDataStopCatchup.as_view()), #actualiza la tabla stopcatchup
    path('endcatchup/', UpdateDataEndCatchup.as_view()), #actualiza la tabla endcatchup
    path('stopvod/', UpdateDataStopVOD.as_view()), #actualiza la tabla stopvod
    path('endvod/', UpdateDataEndVOD.as_view()), #actualiza la tabla endvod
    path('home/<int:days>/', TelemetriaHome.as_view()), #vista de datos en home

]
