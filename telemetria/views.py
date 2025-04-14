# Importa las bibliotecas y módulos necesarios
from collections import defaultdict

from django.views import View  

from django.views.decorators.csrf import csrf_exempt  # Desactiva la protección CSRF
from django.views.decorators.http import require_POST  # Requiere que la solicitud sea de tipo POST

from django.utils.decorators import method_decorator
from django.utils import timezone

from django.db import IntegrityError
from django.db import transaction, DatabaseError

from django.db.models import Q
from django.db.models import Sum
from django.db.models import Max

from django.core.exceptions import ObjectDoesNotExist

from django.http import JsonResponse  # Devuelve respuestas HTTP en formato JSON

from rest_framework.response import Response  # Clase para manejar respuestas HTTP
from rest_framework.views import APIView  # Clase base para vistas basadas en clases en Django REST framework
from rest_framework import viewsets  # Clase para definir vistas de conjunto en Django REST framework
from rest_framework import status

from rest_framework.exceptions import ValidationError

from rest_framework.permissions import IsAuthenticated #validar la permission
from rest_framework.permissions import AllowAny #no validar la permission

from datetime import datetime, timedelta

from functools import wraps

import json
import gzip
import orjson
import logging
import time
import hashlib
import requests
import plotly.graph_objects as go
from io import BytesIO
import base64

import matplotlib
matplotlib.use('Agg')  # Establece Agg como backend
import matplotlib.pyplot as plt
from collections import defaultdict
from typing import Dict, Any

from .models import Telemetria, MergedTelemetricOTT, MergedTelemetricDVB, MergedTelemetricStopCatchup, MergedTelemetricEndCatchup, MergedTelemetricStopVOD, MergedTelemetricEndVOD  # Importa los modelos necesarios
from .serializer import MergedTelemetricEndCatchupSerializer, MergedTelemetricStopCatchupSerializer, TelemetriaSerializer, MergedTelemetricOTTSerializer, MergedTelemetricDVBSerializer, MergedTelemetricEndVODSerializer, MergedTelemetricStopVODSerializer# Importa los serializadores necesarios

logger = logging.getLogger(__name__)

# Clase para manejar la comunicación con el sistema CV
class CVClient:
    def __init__(self, base_url="https://cv10.panaccess.com", mode="json", jsonp_timeout=5000):
        self.base_url = base_url
        self.mode = mode
        self.jsonp_timeout = jsonp_timeout
        self.session_id = None

    # Función para generar un hash MD5 del password
    def md5_hash(self, password):
        salt = "_panaccess"
        hashed_password = hashlib.md5((password + salt).encode()).hexdigest()
        return hashed_password

    # Función para serializar los parámetros en una cadena de consulta
    def serialize(self, obj):
        return "&".join(f"{k}={v}" for k, v in obj.items())

    # Función genérica para realizar llamadas a funciones del sistema CV
    def call(self, func_name, parameters):
        url = f"{self.base_url}?f={func_name}&requestMode=function"
        
        # Añadir el sessionId a los parámetros si no es una llamada de login
        if self.session_id is not None and func_name != 'login':
            parameters['sessionId'] = self.session_id
        
        param_string = self.serialize(parameters)
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        response = requests.post(url, data=param_string, headers=headers)
        
        # Manejo de la respuesta de la API
        if response.status_code == 200:
            try:
                result = response.json()
            except ValueError:
                result = {
                    "success": False,
                    "errorCode": "json_parse_error",
                    "errorMessage": "Failed to parse JSON response"
                }
            return result
        else:
            return {
                "success": False,
                "errorCode": "unknown_error",
                "errorMessage": f"({response.status_code}) An unknown error occurred!"
            }

    # Función para realizar el login en el sistema CV
    def login(self, api_token, username, password):
        password_hash = self.md5_hash(password)
        
        result = self.call(
            "login", 
            {
                "username": username,
                "password": password_hash,
                "apiToken": api_token
            }
        )
        
        # Manejo de la respuesta del login
        if result.get("success"):
            session_id = result.get("answer")
            if session_id:
                self.session_id = session_id
                return True, None
            else:
                return False, "Username or password wrong"
        else:
            return False, result.get("errorMessage")

    # Función para obtener la lista de registros de telemetría con paginación
    def get_list_of_telemetry_records(self, offset, limit):
        return self.call(
            "getListOfTelemetryRecords",
            {
                "sessionId": self.session_id,
                "offset": offset,
                "limit": limit,
                "orderBy": "recordId",
                "orderDir": "DESC"
            }
        )

# Función para verificar si la base de datos está vacía
def is_database_empty():
    return not Telemetria.objects.exists()

# Función para obtener la hora de un timestamp
def get_time_date(timestamp):
    data = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    return data.hour

# Función para obtener la fecha de un timestamp
def get_data_date(timestamp):
    data = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    return data.date().isoformat()

# Función para extraer detalles del timestamp y añadirlos a los registros
def extract_timestamp_details(data):
    for record in data:
        try:
            timestamp = record["timestamp"]
            record["dataDate"] = get_data_date(timestamp)
            record["timeDate"] = get_time_date(timestamp)
        except (ValueError, KeyError) as e:
            logger.error(f"Error processing timestamp for record {record}: {e}")
            record["dataDate"] = None
            record["timeDate"] = None
    return data

# Función para almacenar los datos de telemetría en la base de datos
def store_telemetry_data(data_batch):
    batch_size = 500  # Reducimos el tamaño del lote
    chunk_size = 100  # Tamaño para verificar registros existentes
    total_processed = 0
    total_invalid = 0

    # Procesar los datos en chunks más pequeños
    for i in range(0, len(data_batch), chunk_size):
        chunk = data_batch[i:i + chunk_size]
        
        # Obtener los recordIds del chunk actual
        record_ids = {item['recordId'] for item in chunk if 'recordId' in item}
        existing_record_ids = set(Telemetria.objects.filter(
            recordId__in=record_ids
        ).values_list('recordId', flat=True))

        with transaction.atomic():
            telemetry_objects = []
            for item in chunk:
                if item.get('recordId') not in existing_record_ids:
                    serializer = TelemetriaSerializer(data=item)
                    if serializer.is_valid():
                        telemetry_object = Telemetria(**serializer.validated_data)
                        telemetry_objects.append(telemetry_object)
                        total_processed += 1
                    else:
                        logger.warning(f"Invalid data: {serializer.errors}")
                        total_invalid += 1

                # Almacenar en la base de datos cuando alcance el batch_size
                if len(telemetry_objects) >= batch_size:
                    Telemetria.objects.bulk_create(telemetry_objects, ignore_conflicts=True)
                    logger.info(f"Inserted batch of {len(telemetry_objects)} objects")
                    telemetry_objects = []

            # Almacenar los objetos restantes
            if telemetry_objects:
                Telemetria.objects.bulk_create(telemetry_objects, ignore_conflicts=True)
                logger.info(f"Inserted final batch of {len(telemetry_objects)} objects")

    logger.info(f"Total processed: {total_processed}, Total invalid: {total_invalid}")
    return total_processed, total_invalid

# Función para obtener todos los datos de telemetría con paginación y guardarlos directamente
def fetch_and_store_data_streaming(client, limit):
    currentPage = 0
    total_processed = 0
    total_invalid = 0

    while True:
        result = client.get_list_of_telemetry_records(currentPage, limit)
        if not result.get("success"):
            raise Exception(f"Error al obtener datos: {result.get('errorMessage')}")

        data = result.get("answer", {}).get("telemetryRecordEntries", [])
        if not data:
            break

        logger.info(f"Fetched {len(data)} records in page {currentPage}")
        processed_data = extract_timestamp_details(data)
        processed, invalid = store_telemetry_data(processed_data)
        total_processed += processed
        total_invalid += invalid

        currentPage += limit

    return total_processed, total_invalid

# Función para obtener datos de telemetría hasta un recordId específico
def fetch_data_up_to(client, highestRecordId, limit):
    currentPage = 0
    total_processed = 0
    total_invalid = 0
    foundRecord = False

    while True:
        result = client.get_list_of_telemetry_records(currentPage, limit)
        if not result.get("success"):
            raise Exception(f"Error al obtener datos: {result.get('errorMessage')}")

        data = result.get("answer", {}).get("telemetryRecordEntries", [])
        if not data:
            break

        filtered_data = []
        for record in data:
            if record["recordId"] == highestRecordId:
                foundRecord = True
                break
            filtered_data.append(record)

        if filtered_data:
            logger.info(f"Processing {len(filtered_data)} records from page {currentPage}")
            processed_data = extract_timestamp_details(filtered_data)
            processed, invalid = store_telemetry_data(processed_data)
            total_processed += processed
            total_invalid += invalid

        if foundRecord:
            break

        currentPage += limit

    return total_processed, total_invalid

# Funcion para hacer la consulta al CV de telemetry y obtener todos los datos
@method_decorator(csrf_exempt, name='dispatch')
class TestFetchAndStoreTelemetry(View):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            # Credenciales
            username = "yab_analitics"
            password = "Analizar321!"
            cv_token = "AhmLeBqnOJzPZzkeuXKa"
            limit = 100  # Reducido para menor uso de memoria

            # Login en CV
            client = CVClient()
            success, error_message = client.login(cv_token, username, password)
            if not success:
                return JsonResponse({"error": error_message}, status=400)

            # Verificación base de datos
            if is_database_empty():
                message = "Fetched all data"
                total_processed, total_invalid = fetch_and_store_data_streaming(client, limit)
            else:
                highest_record = Telemetria.objects.order_by('-recordId').first()
                highestRecordId = highest_record.recordId if highest_record else None
                total_processed, total_invalid = fetch_data_up_to(client, highestRecordId, limit)
                message = "Fetched data up to highest recordId"

            return JsonResponse({
                "message": message,
                "total_processed": total_processed,
                "total_invalid": total_invalid
            })

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return JsonResponse({"error": str(e)}, status=500)


#--------------------------------------------------------------------------------#

def timeit(func):
    @wraps(func)
    def timeit_wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        total_time = end_time - start_time
        logger.info(f'{func.__name__} took {total_time:.4f} seconds')
        return result
    return timeit_wrapper

#--------------------------------------------------------------------------------#

## actualización de los datos de OTT
class UpdateDataOTT(APIView):
    """
    API para actualizar los datos en la tabla MergedTelemetricOTT fusionando registros de Telemetria.
    Optimizada para bajo uso de memoria en Heroku (evita R14).
    """

    @staticmethod
    def get_valid_fields(data):
        """
        Filtra los campos no válidos del diccionario `data` y devuelve un diccionario
        con solo los campos válidos del modelo MergedTelemetricOTT.
        """
        valid_fields = {field.name for field in MergedTelemetricOTT._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def data_ott_stream():
        """
        Fusiona solo el campo `dataName` para registros de actionId=8 usando los registros con actionId=7.
        Utiliza streams para bajo consumo de RAM.
        """
        try:
            # Diccionario con dataId -> dataName para actionId=7
            actionid7_dict = dict(
                Telemetria.objects
                .filter(actionId=7, dataId__isnull=False)
                .values_list('dataId', 'dataName')
            )

            # Iterar solo los registros actionId=8, evitando carga completa
            for item in Telemetria.objects.filter(actionId=8).iterator():
                if item.dataId in actionid7_dict:
                    item.dataName = actionid7_dict[item.dataId]
                yield item

        except Exception as e:
            logger.error(f"Error en data_ott_stream: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=100):
        """
        Inserta registros en MergedTelemetricOTT en lotes (batch_size) para evitar exceso de memoria.
        """
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricOTT.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        Maneja la solicitud POST para actualizar los datos de MergedTelemetricOTT.
        Procesa datos por lotes para evitar errores R14 en Heroku.
        """
        try:
            # Máximo recordId existente en destino
            id_maximo_registro = MergedTelemetricOTT.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            registros_filtrados = []
            total_insertados = 0

            for record in self.data_ott_stream():
                if record.recordId and record.recordId > id_maximo_registro:
                    fields = self.get_valid_fields(record.__dict__)
                    nuevo = MergedTelemetricOTT(**fields)
                    registros_filtrados.append(nuevo)

                    # Insertar por lotes
                    if len(registros_filtrados) >= 100:
                        self.bulk_insert_merged_data(registros_filtrados)
                        total_insertados += len(registros_filtrados)
                        registros_filtrados = []

            # Insertar registros restantes
            if registros_filtrados:
                self.bulk_insert_merged_data(registros_filtrados)
                total_insertados += len(registros_filtrados)

            if total_insertados == 0:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            return Response({"message": f"Inserción exitosa ({total_insertados} registros)"}, status=status.HTTP_200_OK)

        except IntegrityError as e:
            logger.error(f"Error de integridad en UpdateDataOTT: {e}")
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ValidationError as e:
            logger.warning(f"Error de validación en UpdateDataOTT: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception(f"Error inesperado en UpdateDataOTT: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        """
        Maneja la solicitud GET para obtener todos los datos de MergedTelemetricOTT.
        """
        try:
            data = MergedTelemetricOTT.objects.all()
            serializer = MergedTelemetricOTTSerializer(data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error en GET UpdateDataOTT: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

## actualización de los datos de DVB
class UpdateDataDVB(APIView):
    """
    API para actualizar los datos en la tabla MergedTelemetricDVB fusionando registros de Telemetria.
    Optimizada para bajo consumo de memoria (evita error R14).
    """

    @staticmethod
    def get_valid_fields(data):
        valid_fields = {field.name for field in MergedTelemetricDVB._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def data_dvb_stream():
        """
        Generador que fusiona dataName de registros con actionId=5 en los registros con actionId=6.
        """
        try:
            # Diccionario con dataId -> dataName de actionId=5
            actionid5_dict = dict(
                Telemetria.objects
                .filter(actionId=5, dataId__isnull=False)
                .values_list('dataId', 'dataName')
            )

            # Iterar por los registros de actionId=6 (streaming)
            for item in Telemetria.objects.filter(actionId=6).iterator():
                if item.dataId in actionid5_dict and not item.dataName:
                    item.dataName = actionid5_dict[item.dataId]
                yield item

        except Exception as e:
            logger.error(f"Error en data_dvb_stream: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=100):
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricDVB.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        Maneja la solicitud POST para actualizar MergedTelemetricDVB con bajo consumo de RAM.
        """
        try:
            id_maximo_registro = MergedTelemetricDVB.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0
            registros_filtrados = []
            total_insertados = 0

            for record in self.data_dvb_stream():
                if record.recordId and record.recordId > id_maximo_registro:
                    nuevo = MergedTelemetricDVB(**self.get_valid_fields(record.__dict__))
                    registros_filtrados.append(nuevo)

                    if len(registros_filtrados) >= 100:
                        self.bulk_insert_merged_data(registros_filtrados)
                        total_insertados += len(registros_filtrados)
                        registros_filtrados = []

            # Insertar los que queden
            if registros_filtrados:
                self.bulk_insert_merged_data(registros_filtrados)
                total_insertados += len(registros_filtrados)

            if total_insertados == 0:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            return Response({"message": f"Inserción exitosa ({total_insertados} registros)"}, status=status.HTTP_200_OK)

        except IntegrityError as e:
            logger.error(f"Error de integridad en UpdateDataDVB: {e}")
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ValidationError as e:
            logger.warning(f"Error de validación en UpdateDataDVB: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception(f"Error inesperado en UpdateDataDVB: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        try:
            data = MergedTelemetricDVB.objects.all()
            serializer = MergedTelemetricDVBSerializer(data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error en GET UpdateDataDVB: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

## actualización de los datos de catchup pausado
class UpdateDataStopCatchup(APIView):
    """
    API optimizada para actualizar la tabla MergedTelemetricStopCatchup con bajo uso de RAM (previene R14).
    """

    @staticmethod
    def get_valid_fields(data):
        valid_fields = {field.name for field in MergedTelemetricStopCatchup._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def data_stop_stream():
        """
        Generador que fusiona dataName de registros con actionId=16 en registros con actionId=17.
        """
        try:
            actionid16_dict = dict(
                Telemetria.objects
                .filter(actionId=16, dataId__isnull=False)
                .values_list('dataId', 'dataName')
            )

            for item in Telemetria.objects.filter(actionId=17).iterator():
                if item.dataId in actionid16_dict and not item.dataName:
                    item.dataName = actionid16_dict[item.dataId]
                yield item

        except Exception as e:
            logger.error(f"Error en data_stop_stream: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=100):
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricStopCatchup.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        POST: Inserta registros nuevos fusionados a partir de registros con actionId=17.
        """
        try:
            id_maximo_registro = MergedTelemetricStopCatchup.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0
            registros_filtrados = []
            total_insertados = 0

            for record in self.data_stop_stream():
                if record.recordId and record.recordId > id_maximo_registro:
                    nuevo = MergedTelemetricStopCatchup(**self.get_valid_fields(record.__dict__))
                    registros_filtrados.append(nuevo)

                    if len(registros_filtrados) >= 100:
                        self.bulk_insert_merged_data(registros_filtrados)
                        total_insertados += len(registros_filtrados)
                        registros_filtrados = []

            if registros_filtrados:
                self.bulk_insert_merged_data(registros_filtrados)
                total_insertados += len(registros_filtrados)

            if total_insertados == 0:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            return Response({"message": f"Inserción exitosa ({total_insertados} registros)"}, status=status.HTTP_200_OK)

        except IntegrityError as e:
            logger.error(f"Error de integridad en UpdateDataStopCatchup: {e}")
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ValidationError as e:
            logger.warning(f"Error de validación en UpdateDataStopCatchup: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception(f"Error inesperado en UpdateDataStopCatchup: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        """
        GET: Devuelve todos los registros actuales en MergedTelemetricStopCatchup.
        """
        try:
            data = MergedTelemetricStopCatchup.objects.all()
            serializer = MergedTelemetricStopCatchupSerializer(data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error en GET UpdateDataStopCatchup: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

## actualización de los datos de catchup terminado
class UpdateDataEndCatchup(APIView):
    """
    API para actualizar la tabla MergedTelemetricEndCatchup sin riesgo de R14.
    """

    @staticmethod
    def get_valid_fields(data):
        valid_fields = {field.name for field in MergedTelemetricEndCatchup._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def data_end_stream():
        """
        Fusiona el campo dataName de registros actionId=16 en los registros actionId=18.
        Procesa en streaming para evitar uso excesivo de RAM.
        """
        try:
            actionid16_dict = dict(
                Telemetria.objects
                .filter(actionId=16, dataId__isnull=False)
                .values_list('dataId', 'dataName')
            )

            for item in Telemetria.objects.filter(actionId=18).iterator():
                if item.dataId in actionid16_dict and not item.dataName:
                    item.dataName = actionid16_dict[item.dataId]
                yield item

        except Exception as e:
            logger.error(f"Error en data_end_stream: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=100):
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricEndCatchup.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        POST: Inserta registros fusionados en MergedTelemetricEndCatchup usando streaming y lotes.
        """
        try:
            id_maximo_registro = MergedTelemetricEndCatchup.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0
            registros_filtrados = []
            total_insertados = 0

            for record in self.data_end_stream():
                if record.recordId and record.recordId > id_maximo_registro:
                    nuevo = MergedTelemetricEndCatchup(**self.get_valid_fields(record.__dict__))
                    registros_filtrados.append(nuevo)

                    if len(registros_filtrados) >= 100:
                        self.bulk_insert_merged_data(registros_filtrados)
                        total_insertados += len(registros_filtrados)
                        registros_filtrados = []

            if registros_filtrados:
                self.bulk_insert_merged_data(registros_filtrados)
                total_insertados += len(registros_filtrados)

            if total_insertados == 0:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            return Response({"message": f"Inserción exitosa ({total_insertados} registros)"}, status=status.HTTP_200_OK)

        except IntegrityError as e:
            logger.error(f"Error de integridad en UpdateDataEndCatchup: {e}")
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ValidationError as e:
            logger.warning(f"Error de validación en UpdateDataEndCatchup: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception(f"Error inesperado en UpdateDataEndCatchup: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        """
        GET: Devuelve todos los registros de MergedTelemetricEndCatchup.
        """
        try:
            data = MergedTelemetricEndCatchup.objects.all()
            serializer = MergedTelemetricEndCatchupSerializer(data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error en GET UpdateDataEndCatchup: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

## actualización de los datos de VOD pausados
class UpdateDataStopVOD(APIView):
    """
    API optimizada para actualizar la tabla MergedTelemetricStopVOD sin riesgo de R14.
    """

    @staticmethod
    def get_valid_fields(data):
        valid_fields = {field.name for field in MergedTelemetricStopVOD._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def data_stop_stream():
        """
        Generador que fusiona dataName de registros actionId=13 en los registros actionId=14.
        Procesa en streaming para evitar uso excesivo de RAM.
        """
        try:
            actionid13_dict = dict(
                Telemetria.objects
                .filter(actionId=13, dataId__isnull=False)
                .values_list('dataId', 'dataName')
            )

            for item in Telemetria.objects.filter(actionId=14).iterator():
                if item.dataId in actionid13_dict and not item.dataName:
                    item.dataName = actionid13_dict[item.dataId]
                yield item

        except Exception as e:
            logger.error(f"Error en data_stop_stream: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=100):
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricStopVOD.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        POST: Inserta registros fusionados en MergedTelemetricStopVOD usando streaming y lotes.
        """
        try:
            id_maximo_registro = MergedTelemetricStopVOD.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0
            registros_filtrados = []
            total_insertados = 0

            for record in self.data_stop_stream():
                if record.recordId and record.recordId > id_maximo_registro:
                    nuevo = MergedTelemetricStopVOD(**self.get_valid_fields(record.__dict__))
                    registros_filtrados.append(nuevo)

                    if len(registros_filtrados) >= 100:
                        self.bulk_insert_merged_data(registros_filtrados)
                        total_insertados += len(registros_filtrados)
                        registros_filtrados = []

            if registros_filtrados:
                self.bulk_insert_merged_data(registros_filtrados)
                total_insertados += len(registros_filtrados)

            if total_insertados == 0:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            return Response({"message": f"Inserción exitosa ({total_insertados} registros)"}, status=status.HTTP_200_OK)

        except IntegrityError as e:
            logger.error(f"Error de integridad en UpdateDataStopVOD: {e}")
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ValidationError as e:
            logger.warning(f"Error de validación en UpdateDataStopVOD: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception(f"Error inesperado en UpdateDataStopVOD: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        """
        GET: Devuelve todos los registros de MergedTelemetricStopVOD.
        """
        try:
            data = MergedTelemetricStopVOD.objects.all()
            serializer = MergedTelemetricStopVODSerializer(data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error en GET UpdateDataStopVOD: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ## actualización de los datos de VOD terminado
class UpdateDataEndVOD(APIView):
    """
    API optimizada para actualizar MergedTelemetricEndVOD sin riesgo de R14.
    """

    @staticmethod
    def get_valid_fields(data):
        valid_fields = {field.name for field in MergedTelemetricEndVOD._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def data_end_stream():
        """
        Generador que fusiona dataName de registros actionId=13 en registros actionId=15.
        Procesamiento por streaming.
        """
        try:
            actionid13_dict = dict(
                Telemetria.objects
                .filter(actionId=13, dataId__isnull=False)
                .values_list('dataId', 'dataName')
            )

            for item in Telemetria.objects.filter(actionId=15).iterator():
                if item.dataId in actionid13_dict and not item.dataName:
                    item.dataName = actionid13_dict[item.dataId]
                yield item

        except Exception as e:
            logger.error(f"Error en data_end_stream: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=100):
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricEndVOD.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        POST: Inserta registros fusionados en MergedTelemetricEndVOD en lotes seguros.
        """
        try:
            id_maximo_registro = MergedTelemetricEndVOD.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0
            registros_filtrados = []
            total_insertados = 0

            for record in self.data_end_stream():
                if record.recordId and record.recordId > id_maximo_registro:
                    nuevo = MergedTelemetricEndVOD(**self.get_valid_fields(record.__dict__))
                    registros_filtrados.append(nuevo)

                    if len(registros_filtrados) >= 100:
                        self.bulk_insert_merged_data(registros_filtrados)
                        total_insertados += len(registros_filtrados)
                        registros_filtrados = []

            if registros_filtrados:
                self.bulk_insert_merged_data(registros_filtrados)
                total_insertados += len(registros_filtrados)

            if total_insertados == 0:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            return Response({"message": f"Inserción exitosa ({total_insertados} registros)"}, status=status.HTTP_200_OK)

        except IntegrityError as e:
            logger.error(f"Error de integridad en UpdateDataEndVOD: {e}")
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ValidationError as e:
            logger.warning(f"Error de validación en UpdateDataEndVOD: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception(f"Error inesperado en UpdateDataEndVOD: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        """
        GET: Devuelve todos los registros de MergedTelemetricEndVOD.
        """
        try:
            data = MergedTelemetricEndVOD.objects.all()
            serializer = MergedTelemetricEndVODSerializer(data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error en GET UpdateDataEndVOD: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TelemetriaDaysOTT(APIView):
    def get_filtered_data(self, days):
        """
        Devuelve un iterador sobre los registros del modelo MergedTelemetricOTT
        filtrados por el rango de fechas correspondiente a los últimos `days` días,
        junto con la fecha de inicio y fin del filtro.
        Si `days` es 0 o negativo, devuelve todos los registros y fechas None.
        """
        try:
            today = datetime.now().date()
            start_date = None
            if days > 0:
                start_date = today - timedelta(days=days)
                queryset = MergedTelemetricOTT.objects.filter(dataDate__range=[start_date, today]).iterator()
            else:
                queryset = MergedTelemetricOTT.objects.all().iterator()
            return queryset, start_date, today
        except Exception as e:
            raise ValueError(f"Error al filtrar los datos: {str(e)}")
    

    def compute_all(self, dataOTT):
        """
        Procesa todos los registros de telemetría OTT para calcular:
        - Duración total en horas
        - Duración por evento
        - Conteo por evento
        - Duración por franja horaria (madrugada, mañana, tarde, noche)
        - Duración y conteo por franja horaria para cada tipo de evento
        """
        duration = 0
        data_by_franja = defaultdict(float)
        data_by_event = defaultdict(float)
        count_by_event = defaultdict(int)
        franja_ranges = {
            "Madrugada": (0, 5),
            "Mañana": (5, 12),
            "Tarde": (12, 18),
            "Noche": (18, 24)
        }
        franja_events = {k: defaultdict(float) for k in franja_ranges}
        franja_counts = {k: defaultdict(int) for k in franja_ranges}

        for item in dataOTT:
            horas = item.dataDuration / 3600 if item.dataDuration else 0
            duration += horas
            count_by_event[item.dataName] += 1
            data_by_event[item.dataName] += horas
            if item.timeDate is not None:
                for franja, (ini, fin) in franja_ranges.items():
                    if ini <= item.timeDate < fin:
                        data_by_franja[franja] += horas
                        franja_events[franja][item.dataName] += horas
                        franja_counts[franja][item.dataName] += 1
                        break

        return {
            "total_duration": round(duration, 2),
            "data_by_franja": {k: round(v, 2) for k, v in data_by_franja.items()},
            "data_by_event": {k: round(v, 2) for k, v in data_by_event.items()},
            "count_by_event": dict(count_by_event),
            "franja_events": {k: {kk: round(vv, 2) for kk, vv in v.items()} for k, v in franja_events.items()},
            "franja_counts": {k: dict(v) for k, v in franja_counts.items()}
        }

    def generate_graph(self, labels, values, title, y2_values=None, show_values=False):
        """
        Genera un gráfico de barras (y opcionalmente líneas) usando Plotly.
        Representa duración en horas y cantidad de vistas para los canales OTT.

        - labels: lista de nombres de canal/evento
        - values: horas vistas
        - y2_values: cantidad de vistas
        - show_values: muestra texto sobre las barras
        """
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=labels, y=values, name='Horas Vistas',
            marker_color='pink', opacity=0.7,
            text=[f"{v:.2f}" for v in values] if show_values else None,
            textposition='outside' if show_values else None
        ))
        if y2_values:
            fig.add_trace(go.Scatter(
                x=labels, y=y2_values,
                mode='lines+markers+text', name='Veces Vistas',
                marker=dict(color='blue', size=8), line=dict(width=2),
                text=[f"{v}" for v in y2_values], textposition="top center"
            ))
        fig.update_layout(
            title=title, xaxis_title='Canales',
            yaxis=dict(type='log', title=dict(text='Horas Vistas', font=dict(color='pink'))),
            yaxis2=dict(type='log', title=dict(text='Veces Vistas', font=dict(color='blue')),
                        overlaying='y', side='right'),
            template='plotly_white',
            xaxis=dict(tickangle=45),
            height=600, margin=dict(b=150)
        )
        return fig.to_json()
    
    def generate_pie_chart(self, data_by_franja):
        """
        Genera una gráfica de torta en formato imagen base64 para franja horaria total.
        `data_dict` debe ser un diccionario con etiquetas y valores.
        """
        try:
            labels = list(data_by_franja.keys())
            values = list(data_by_franja.values())

            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                textinfo='label+percent',
                insidetextorientation='radial'
            )])
            fig.update_layout(title="Distribución de horas por franja horaria (OTT)")

            buffer = BytesIO()
            fig.write_image(buffer, format='png')
            buffer.seek(0)
            encoded_image = base64.b64encode(buffer.read()).decode('utf-8')
            return encoded_image
        except Exception as e:
            return None

    def get(self, request, days=7):
        """
        Endpoint GET que agrupa las estadísticas de telemetría OTT para los últimos `days` días.
        Retorna:
        - Total de duración
        - Duración por franja horaria y por evento
        - Cantidad de eventos por tipo y franja horaria
        - Gráficos por franja horaria y general
        """
        try:
            dataOTT, start_date, end_date = self.get_filtered_data(int(days))
            metrics = self.compute_all(dataOTT)

            sorted_channels = sorted(metrics['data_by_event'], key=metrics['data_by_event'].get, reverse=True)
            hours = [metrics['data_by_event'][ch] for ch in sorted_channels]
            counts = [metrics['count_by_event'].get(ch, 0) for ch in sorted_channels]

            graph_ott = self.generate_graph(sorted_channels, hours, "Total OTT", y2_values=counts, show_values=True)
            franja_graphs = {}
            for franja in ["Madrugada", "Mañana", "Tarde", "Noche"]:
                chs = sorted(metrics['franja_events'][franja], key=metrics['franja_events'][franja].get, reverse=True)
                hrs = [metrics['franja_events'][franja][ch] for ch in chs]
                cnts = [metrics['franja_counts'][franja].get(ch, 0) for ch in chs]
                franja_graphs[franja] = self.generate_graph(chs, hrs, f"OTT {franja}", y2_values=cnts, show_values=True)

            # Gráfico de torta con franja horaria total
            pie_chart = self.generate_pie_chart(metrics['data_by_franja'])

            return Response({
                "totals": {
                    "total_duration_ott": metrics['total_duration'],
                    "franja_horaria_ott": metrics['data_by_franja'],
                    "event_duration": metrics['data_by_event'],
                    "event_count": metrics['count_by_event'],
                    "franja_event_duration": metrics['franja_events'],
                    "franja_event_count": metrics['franja_counts'],
                    "total_event_count": sum(metrics['count_by_event'].values()),
                    "start_date": str(start_date),
                    "end_date": str(end_date)
                },
                "graphs": {
                    "graph_ott": graph_ott,
                    "graph_franjas": franja_graphs,
                    "graph_pie": pie_chart
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TelemetriaDateOTT(APIView):
    def get_filtered_data(self, start_date, end_date):
        """
        Devuelve un iterador de registros de MergedTelemetricOTT filtrado por fechas.
        Utiliza .iterator() para evitar cargar todo en memoria y reducir uso de RAM.
        """
        try:
            start_date, end_date = sorted([start_date, end_date])
            return MergedTelemetricOTT.objects.filter(dataDate__range=[start_date, end_date]).iterator()
        except ValueError as e:
            raise ValueError(f"Error al filtrar los datos: {str(e)}")

    def compute_metrics(self, dataOTT):
        """
        Procesa todos los registros filtrados para calcular:
        - Duración total
        - Duración por evento
        - Conteo por evento
        - Duración por franja horaria
        - Duración y conteo por franja para cada evento
        """
        duration = 0
        data_by_franja = defaultdict(float)
        data_by_event = defaultdict(float)
        count_by_event = defaultdict(int)

        franja_ranges = {
            "Madrugada": (0, 5),
            "Mañana": (5, 12),
            "Tarde": (12, 18),
            "Noche": (18, 24)
        }
        franja_events = {k: defaultdict(float) for k in franja_ranges}
        franja_counts = {k: defaultdict(int) for k in franja_ranges}

        for item in dataOTT:
            horas = item.dataDuration / 3600 if item.dataDuration else 0
            duration += horas
            count_by_event[item.dataName] += 1
            data_by_event[item.dataName] += horas

            if item.timeDate is not None:
                for franja, (ini, fin) in franja_ranges.items():
                    if ini <= item.timeDate < fin:
                        data_by_franja[franja] += horas
                        franja_events[franja][item.dataName] += horas
                        franja_counts[franja][item.dataName] += 1
                        break

        return {
            "total_duration": round(duration, 2),
            "data_by_franja": {k: round(v, 2) for k, v in data_by_franja.items()},
            "data_by_event": {k: round(v, 2) for k, v in data_by_event.items()},
            "count_by_event": dict(count_by_event),
            "franja_events": {k: {kk: round(vv, 2) for kk, vv in v.items()} for k, v in franja_events.items()},
            "franja_counts": {k: dict(v) for k, v in franja_counts.items()}
        }

    def generate_chart(self, labels, values, title, y2_values=None, show_values=False):
        """
        Genera un gráfico de barras y línea superpuesta con Plotly para:
        - Duración total (barras)
        - Cantidad de vistas (línea)
        """
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=labels, y=values, name='Horas Vistas',
            marker_color='pink', opacity=0.7,
            text=[f"{v:.2f}" for v in values] if show_values else None,
            textposition='outside' if show_values else None
        ))

        if y2_values:
            fig.add_trace(go.Scatter(
                x=labels, y=y2_values,
                mode='lines+markers+text', name='Veces Vistas',
                marker=dict(color='blue', size=8), line=dict(width=2),
                text=[f"{v}" for v in y2_values], textposition="top center"
            ))

        fig.update_layout(
            title=title,
            xaxis_title='Canales',
            yaxis=dict(type='log', title=dict(text='Horas Vistas', font=dict(color='pink'))),
            yaxis2=dict(type='log', title=dict(text='Veces Vistas', font=dict(color='blue')),
                        overlaying='y', side='right'),
            template='plotly_white',
            xaxis=dict(tickangle=45),
            height=600,
            margin=dict(b=150)
        )
        return fig.to_json()

    def generate_pie_chart(self, data_dict, title):
        """
        Genera un gráfico de torta con la distribución de duración por franja horaria.
        """
        labels = list(data_dict.keys())
        values = list(data_dict.values())

        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hoverinfo='label+percent',
            textinfo='label+value'
        )])

        fig.update_layout(
            title_text=title,
            template='plotly_white',
            height=500
        )

        return fig.to_image(format="png").decode("utf-8")

    def get(self, request, start, end):
        """
        Endpoint GET que recibe dos fechas (start y end) y retorna:
        - Duración total entre fechas
        - Fecha de inicio y fin
        - Cantidad total de eventos
        - Duración por franja horaria y evento
        - Conteo por evento y por franja
        - Gráficos totales y por franja
        - Gráfico de torta de franja horaria
        """
        try:
            start_date = datetime.strptime(start, "%Y-%m-%d").date()
            end_date = datetime.strptime(end, "%Y-%m-%d").date()
            dataOTT = list(self.get_filtered_data(start_date, end_date))
            metrics = self.compute_metrics(dataOTT)

            sorted_channels = sorted(metrics['data_by_event'], key=metrics['data_by_event'].get, reverse=True)
            hours = [metrics['data_by_event'][ch] for ch in sorted_channels]
            counts = [metrics['count_by_event'].get(ch, 0) for ch in sorted_channels]

            graph_ott = self.generate_chart(sorted_channels, hours, "Total OTT", y2_values=counts, show_values=True)

            franja_graphs = {}
            for franja in ["Madrugada", "Mañana", "Tarde", "Noche"]:
                chs = sorted(metrics['franja_events'][franja], key=metrics['franja_events'][franja].get, reverse=True)
                hrs = [metrics['franja_events'][franja][ch] for ch in chs]
                cnts = [metrics['franja_counts'][franja].get(ch, 0) for ch in chs]
                franja_graphs[franja] = self.generate_chart(chs, hrs, f"OTT {franja}", y2_values=cnts, show_values=True)

            pie_chart = self.generate_pie_chart(metrics['data_by_franja'])

            return Response({
                "totals": {
                    "start_date": str(start_date),
                    "end_date": str(end_date),
                    "total_duration_ott": metrics['total_duration'],
                    "total_event_count": sum(metrics["count_by_event"].values()),
                    "franja_horaria_ott": metrics['data_by_franja'],
                    "event_duration": metrics['data_by_event'],
                    "event_count": metrics['count_by_event'],
                    "franja_event_duration": metrics['franja_events'],
                    "franja_event_count": metrics['franja_counts']
                },
                "graphs": {
                    "graph_ott": graph_ott,
                    "graph_franjas": franja_graphs,
                    "graph_franja_pie": pie_chart
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TelemetriaDaysDvb(APIView):
    def get_filtered_data(self, days):
        """
        Devuelve un iterador sobre los registros del modelo MergedTelemetricDVB
        filtrados por el rango de fechas correspondiente a los últimos `days` días.
        Si `days` es 0 o negativo, devuelve todos los registros.
        """
        try:
            today = datetime.now().date()
            if days > 0:
                start_date = today - timedelta(days=days)
                return MergedTelemetricDVB.objects.filter(dataDate__range=[start_date, today]).iterator(), start_date, today
            return MergedTelemetricDVB.objects.all().iterator(), None, today
        except Exception as e:
            raise ValueError(f"Error al filtrar los datos: {str(e)}")

    def dataRangeDVB(self, days):
        """
        Calcula la duración total de los eventos DVB para los últimos `days` días.
        """
        try:
            dataDVB, start_date, today = self.get_filtered_data(days)
            durationDVB = sum(item.dataDuration if item.dataDuration is not None else 0 for item in dataDVB) / 3600
            return {"duration": round(durationDVB, 2), "start_date": start_date, "end_date": today}
        except Exception as e:
            return None

    def franjaHorarioDVB(self, days):
        """
        Calcula la duración total por franja horaria (Madrugada, Mañana, Tarde, Noche).
        """
        try:
            dataDVB, _, _ = self.get_filtered_data(days)
            data_duration_by_franja = defaultdict(int)
            franjas = {
                "Madrugada": (0, 5),
                "Mañana": (5, 12),
                "Tarde": (12, 18),
                "Noche": (18, 24)
            }

            for item in dataDVB:
                hora = item.timeDate
                for franja, limites in franjas.items():
                    if limites[0] <= hora < limites[1]:
                        data_duration_by_franja[franja] += item.dataDuration / 3600 if item.dataDuration else 0

            return {franja: round(duration, 2) for franja, duration in data_duration_by_franja.items()}

        except ValidationError as e:
            print(f"Error de validación durante la serialización: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la serialización: {e}")
            return None

    def listEventDVB(self, days):
        """
        Calcula la duración total por tipo de evento DVB (dataName) en horas.
        """
        try:
            dataDVB, _, _ = self.get_filtered_data(days)
            data_duration_by_name = defaultdict(float)
            for item in dataDVB:
                data_duration_by_name[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0
            return {data_name: round(duration, 2) for data_name, duration in data_duration_by_name.items()}

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def franjaHorarioEventDVB(self, days):
        """
        Calcula la duración por tipo de evento DVB para cada franja horaria.
        """
        try:
            dataDVB, _, _ = self.get_filtered_data(days)
            data_duration_by_franja = defaultdict(lambda: defaultdict(float))
            franjas = {
                "Madrugada": (0, 5),
                "Mañana": (5, 12),
                "Tarde": (12, 18),
                "Noche": (18, 24)
            }

            for item in dataDVB:
                hora = item.timeDate
                for franja, limites in franjas.items():
                    if limites[0] <= hora < limites[1]:
                        data_duration_by_franja[franja][item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

            result = {}
            for franja, data in data_duration_by_franja.items():
                result[franja] = {data_name: round(duration, 2) for data_name, duration in data.items()}
            return result

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def listCountEventDVB(self, days):
        """
        Cuenta la cantidad de eventos por tipo (dataName) para el rango de días dado.
        """
        try:
            dataDVB, _, _ = self.get_filtered_data(days)
            counts = defaultdict(int)
            for item in dataDVB:
                counts[item.dataName] += 1
            return dict(counts)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, days=None):
        """
        Devuelve estadísticas generales sobre la duración y conteo de eventos DVB,
        organizados por tipo y franja horaria.
        """
        try:
            durationDVB = self.dataRangeDVB(days)
            franjaHorariaDVB = self.franjaHorarioDVB(days)
            franjahorariaEventsDVB = self.franjaHorarioEventDVB(days)
            dvbEvents = self.listEventDVB(days)
            listCountEventDVB = self.listCountEventDVB(days)
            return Response(
                {
                    "totaldurationdvb": durationDVB,
                    "franjahorariadvb": franjaHorariaDVB,
                    "franjahorariaeventodvb": franjahorariaEventsDVB,
                    "listDVB": dvbEvents,
                    "listCountEventDVB": listCountEventDVB,
                },
                status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class VODDays(APIView):
    def countVOD(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataVOD = MergedTelemetricStopVOD.objects.filter(dataDate__range=[start_date, today])
            else:
                dataVOD = MergedTelemetricStopVOD.objects.all()

            vod = 0
            for item in dataVOD:
                vod += 1
            
            return vod

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def listEventVOD(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataVOD = MergedTelemetricStopVOD.objects.filter(dataDate__range=[start_date, today])
            else:
                dataVOD = MergedTelemetricStopVOD.objects.all()

            vod = {}
            for item in dataVOD:
                event = item.dataName
                vod[event] = vod.get(event, 0) + 1
            
            return vod

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, days=None):
        try:

            vodCount = self.countVOD(days)
            vodEvents = self.listEventVOD(days)
            return Response(
                {
                    "vodCount":vodCount,
                    "vodeventos": vodEvents,
                },
                status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class CatchupDays(APIView):
    def countCatchup(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataCatchup = MergedTelemetricStopCatchup.objects.filter(dataDate__range=[start_date, today])
            else:
                dataCatchup = MergedTelemetricStopCatchup.objects.all()

            vod = 0
            for item in dataCatchup:
                vod += 1
            
            return vod

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def listEventCatchup(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataCatchup = MergedTelemetricStopCatchup.objects.filter(dataDate__range=[start_date, today])
            else:
                dataCatchup = MergedTelemetricStopCatchup.objects.all()

            catchup = {}
            for item in dataCatchup:
                event = item.dataName
                catchup[event] = catchup.get(event, 0) + 1
            
            return catchup

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, days=None):
        try:
            catchupCount = self.countCatchup(days)
            catchupEvents = self.listEventCatchup(days)
            return Response(
                {
                    "catchupCount" : catchupCount,
                    "catchupeventos": catchupEvents,
                },
                status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)