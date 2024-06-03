from django.urls import path, include
from rest_framework.routers import DefaultRouter
from telemetria.views import TelemetriaViewSet, MergedTelemetricData , DataTelemetria

# Configura el enrutador para la vista de conjunto TelemetriaViewSet
router = DefaultRouter()
router.register(r'telemetria', TelemetriaViewSet, basename='telemetria')

# Definir las URL para las vistas de Django
urlpatterns = [
    path('telemetria/merged/', MergedTelemetricData.as_view(), name='merged_telemetric_data'),
    path("dataTelemetria/", DataTelemetria, name='data_telemetria')  # Vista para manejar datos de telemetría
]

# Agregar las rutas del enrutador para la vista de conjunto TelemetriaViewSet
urlpatterns += router.urls
