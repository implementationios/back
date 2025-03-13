from django.urls import path
from .views import CatchupDays, TelemetriaDateOTT, TelemetriaDaysDvb, TestFetchAndStoreTelemetry, UpdateDataEndCatchup, UpdateDataEndVOD, UpdateDataOTT, UpdateDataDVB, TelemetriaDaysOTT, UpdateDataStopCatchup, UpdateDataStopVOD, VODDays
from rest_framework_simplejwt.views import TokenObtainPairView


# Definir las URL para las vistas de Django
urlpatterns = [

    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),

    # Ruta para probar la obtención y almacenamiento de datos de telemetría
    path('fetchdata/', TestFetchAndStoreTelemetry.as_view(), name='fetchdata'),

    # Rutas para actualizar diferentes tablas (OTT, DVB, etc.)
    path('ott/', UpdateDataOTT.as_view()),  # Actualiza la tabla ott
    path('dvb/', UpdateDataDVB.as_view()),  # Actualiza la tabla dvb
    path('stopcatchup/', UpdateDataStopCatchup.as_view()),  # Actualiza la tabla stopcatchup
    path('endcatchup/', UpdateDataEndCatchup.as_view()),  # Actualiza la tabla endcatchup
    path('stopvod/', UpdateDataStopVOD.as_view()),  # Actualiza la tabla stopvod
    path('endvod/', UpdateDataEndVOD.as_view()),  # Actualiza la tabla endvod

    # Ruta para datos según la opción
    path('daysott/<int:days>/', TelemetriaDaysOTT.as_view()),  # Vista de datos ott por dias
    path('daysdvb/<int:days>/', TelemetriaDaysDvb.as_view()), # Vista de datos dvb por dias
    path('daysvod/<int:days>/', VODDays.as_view()), # Vista de datos VOD por dias
    path('dayscatchup/<int:days>/', CatchupDays.as_view()), # Vista de datos Catchup por dias

    path("dateott/<str:start>/<str:end>/",TelemetriaDateOTT.as_view()), # Vista de datos ott por fecha
]