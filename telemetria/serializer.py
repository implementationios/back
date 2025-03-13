## permite convertir los modelos en json
from django.core.exceptions import ValidationError

from rest_framework import serializers

from datetime import timezone

from .models import Telemetria, MergedTelemetricOTT, MergedTelemetricDVB, MergedTelemetricStopCatchup, MergedTelemetricEndCatchup, MergedTelemetricStopVOD, MergedTelemetricEndVOD

class TelemetriaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Telemetria
        fields = '__all__'

    def validate_recordId(self, value):
        if value < 0:
            raise serializers.ValidationError("El recordId debe ser mayor a 0")
        return value

class MergedTelemetricOTTSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricOTT
        fields = '__all__'

class MergedTelemetricDVBSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricDVB
        fields = '__all__'

class MergedTelemetricStopCatchupSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricStopCatchup
        fields = '__all__'

class MergedTelemetricEndCatchupSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricEndCatchup
        fields = '__all__'

class MergedTelemetricStopVODSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricStopVOD
        fields = '__all__'

class MergedTelemetricEndVODSerializer(serializers.ModelSerializer):
    class Meta:
        model = MergedTelemetricEndVOD
        fields = '__all__'
