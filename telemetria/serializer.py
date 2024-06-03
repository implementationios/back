## permite convertir los modelos en json
from rest_framework import serializers
from .models import Telemetria, MergedTelemetricOTT, MergedTelemetricDVB, MergedTelemetricStopCatchup, MergedTelemetricEndCatchup, MergedTelemetricStopVOD, MergedTelemetricEndVOD

class TelemetriaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Telemetria
        fields = '__all__'


class MergedTelemetricOTTSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricOTT
        fields = '__all__'

class MergedTelemetricDVBSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricDVB
        fields = '__all__'

class MergedTelemetricCatchupSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricStopCatchup, MergedTelemetricEndCatchup
        fields = '__all__'

class MergedTelemetricVODSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricStopVOD, MergedTelemetricEndVOD
        fields = '__all__'