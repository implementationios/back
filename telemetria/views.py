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
import io
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

# Función para obtener todos los datos de telemetría con paginación
def fetch_all_data(client, limit):
    currentPage = 0
    allTelemetryData = []

    while True:
        result = client.get_list_of_telemetry_records(currentPage, limit)
        if not result.get("success"):
            raise Exception(f"Error al obtener datos: {result.get('errorMessage')}")
        
        data = result.get("answer", {}).get("telemetryRecordEntries", [])
        if not data:
            break
        
        allTelemetryData.extend(data)
        currentPage += limit

    return allTelemetryData

# Función para obtener datos de telemetría hasta un recordId específico
def fetch_data_up_to(client, highestRecordId, limit):
    currentPage = 0
    allTelemetryData = []
    foundRecord = False

    while True:
        result = client.get_list_of_telemetry_records(currentPage, limit)
        if not result.get("success"):
            raise Exception(f"Error al obtener datos: {result.get('errorMessage')}")
        
        data = result.get("answer", {}).get("telemetryRecordEntries", [])
        if not data:
            break
        
        for record in data:
            if record["recordId"] == highestRecordId:
                foundRecord = True
                break
            allTelemetryData.append(record)
        
        if foundRecord:
            break
        
        currentPage += limit

    return allTelemetryData

# Funcion para hacer la consulta al CV de telemetry y obtener todos los datos
@method_decorator(csrf_exempt, name='dispatch')
class TestFetchAndStoreTelemetry(View):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        try:
            # Credenciales proporcionadas para la prueba
            username = "yab_analitics"
            password = "Analizar321!"
            cv_token = "AhmLeBqnOJzPZzkeuXKa"
            limit = 1000  # Podemos reducir este límite si es necesario
            
            # Inicializar el cliente CV y realizar el login
            client = CVClient()
            success, error_message = client.login(cv_token, username, password)
           
            if not success:
                return JsonResponse({"error": error_message}, status=400)
           
            # Verificar si la base de datos está vacía
            if is_database_empty():
                data = fetch_all_data(client, limit)
                message = "Fetched all data"
            else:
                highest_record = Telemetria.objects.order_by('-recordId').first()
                highestRecordId = highest_record.recordId if highest_record else None
                data = fetch_data_up_to(client, highestRecordId, limit)
                message = "Fetched data up to highest recordId"

            # Procesar datos para agregar fecha y hora
            processed_data = extract_timestamp_details(data)
            
            # Almacenar los datos en la base de datos
            total_processed, total_invalid = store_telemetry_data(processed_data)

            return JsonResponse({
                "message": message,
                "total_processed": total_processed,
                "total_invalid": total_invalid,
                "data_count": len(processed_data)
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
    def data_ott():
        """
        Fusiona solo el campo `dataName` para los registros de actionId=8
        que tienen el mismo `dataId` en los registros de actionId=7.
        """
        try:
            # Obtener datos filtrados en una sola consulta
            telemetria_data = Telemetria.objects.filter(actionId__in=[7, 8])

            # Diccionario para mapear dataId -> dataName de actionId=7
            actionid7_dict = {item.dataId: item.dataName for item in telemetria_data if item.actionId == 7 and item.dataId}

            # Lista para almacenar datos fusionados
            merged_data = []

            for item in telemetria_data:
                # Verificar si el registro es de actionId=8 y su dataId tiene un dataName correspondiente en actionId=7
                if item.actionId == 8 and item.dataId in actionid7_dict:
                    # Fusionar solo el campo `dataName`
                    item.dataName = actionid7_dict[item.dataId]

                # Agregar el registro, modificado o no, a la lista final
                merged_data.append(item)

            return merged_data

        except Exception as e:
            logger.error(f"Error en data_ott: {e}")
            return []


    @staticmethod
    def bulk_insert_merged_data(records, batch_size=500):
        """
        Inserta los registros en MergedTelemetricOTT en lotes de batch_size para optimizar la inserción.
        """
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricOTT.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        Maneja la solicitud POST para actualizar los datos de MergedTelemetricOTT.
        """
        try:
            # Obtener datos fusionados
            merged_data = self.data_ott()

            if not merged_data:
                return Response({"message": "No hay datos para actualizar"}, status=status.HTTP_200_OK)

            # Obtener el máximo recordId existente en la tabla destino
            id_maximo_registro = MergedTelemetricOTT.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            # Filtrar los registros nuevos
            registros_filtrados = [
                MergedTelemetricOTT(**self.get_valid_fields(record.__dict__))
                for record in merged_data
                if record.recordId and record.recordId > id_maximo_registro
            ]

            # Verificar si hay nuevos registros
            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                self.bulk_insert_merged_data(registros_filtrados)

            return Response({"message": "Inserción exitosa"}, status=status.HTTP_200_OK)

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
            # Obtiene todos los objetos de la tabla MergedTelemetricOTT en la base de datos
            data = MergedTelemetricOTT.objects.all()

            # Serializa los datos obtenidos utilizando el serializador correspondiente
            serializer = MergedTelemetricOTTSerializer(data, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error en GET UpdateDataOTT: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

## actualización de los datos de DVB
class UpdateDataDVB(APIView):
    """
    API para actualizar los datos en la tabla MergedTelemetricDVB fusionando registros de Telemetria.
    """

    @staticmethod
    def get_valid_fields(data):
        """
        Filtra los campos no válidos del diccionario `data` y devuelve un diccionario
        con solo los campos válidos del modelo MergedTelemetricDVB.
        """
        valid_fields = {field.name for field in MergedTelemetricDVB._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def dataDVB():
        """
        Fusiona solo el campo `dataName` para los registros de actionId=6
        que tienen el mismo `dataId` en los registros de actionId=5.
        """
        try:
            # Obtener todos los registros con actionId=5 y actionId=6
            telemetria_data = Telemetria.objects.filter(actionId__in=[5, 6])

            # Diccionario para mapear dataId -> dataName de actionId=5
            actionid5_dict = {
                item.dataId: item.dataName
                for item in telemetria_data
                if item.actionId == 5 and item.dataId
            }

            # Lista para almacenar registros de actionId=6 con modificaciones en dataName
            updated_data = []

            for item in telemetria_data:
                if item.actionId == 6:
                    # Si el dataId existe en actionId=5, tomar el dataName correspondiente
                    if item.dataId in actionid5_dict and not item.dataName:
                        item.dataName = actionid5_dict[item.dataId]

                    # Agregar el registro de actionId=6 (modificado o no) a la lista final
                    updated_data.append(item)

            return updated_data

        except Exception as e:
            logger.error(f"Error en dataDVB: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=500):
        """
        Inserta los registros en MergedTelemetricDVB en lotes de batch_size para optimizar la inserción.
        """
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricDVB.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        Maneja la solicitud POST para actualizar los datos de MergedTelemetricDVB.
        """
        try:
            # Obtener registros de actionId=6 con dataName fusionado
            updated_data = self.dataDVB()

            if not updated_data:
                return Response({"message": "No hay datos para actualizar"}, status=status.HTTP_200_OK)

            # Obtener el máximo recordId existente en la tabla destino
            id_maximo_registro = MergedTelemetricDVB.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            # Filtrar los registros de actionId=6 que tengan recordId mayor al máximo existente
            registros_filtrados = [
                MergedTelemetricDVB(**self.get_valid_fields(record.__dict__))
                for record in updated_data
                if record.recordId and record.recordId > id_maximo_registro
            ]

            # Verificar si hay registros nuevos para insertar
            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            # Insertar los registros en MergedTelemetricDVB
            with transaction.atomic():
                self.bulk_insert_merged_data(registros_filtrados)

            return Response({"message": "Inserción exitosa"}, status=status.HTTP_200_OK)

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
        """
        Maneja la solicitud GET para obtener todos los datos de MergedTelemetricDVB.
        """
        try:
            # Obtiene todos los objetos de la tabla MergedTelemetricDVB en la base de datos
            data = MergedTelemetricDVB.objects.all()

            # Serializa los datos obtenidos utilizando el serializador correspondiente
            serializer = MergedTelemetricDVBSerializer(data, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error en GET UpdateDataDVB: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

## actualización de los datos de catchup pausado
class UpdateDataStopCatchup(APIView):
    """
    API para actualizar los datos en la tabla MergedTelemetricStopCatchup fusionando registros de Telemetria.
    """

    @staticmethod
    def get_valid_fields(data):
        """
        Filtra los campos no válidos del diccionario `data` y devuelve un diccionario
        con solo los campos válidos del modelo MergedTelemetricStopCatchup.
        """
        valid_fields = {field.name for field in MergedTelemetricStopCatchup._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def dataStop():
        """
        Fusiona solo el campo `dataName` para los registros de actionId=17
        que tienen el mismo `dataId` en los registros de actionId=16.
        """
        try:
            telemetria_data = Telemetria.objects.filter(actionId__in=[16, 17])

            actionid16_dict = {
                item.dataId: item.dataName
                for item in telemetria_data
                if item.actionId == 16 and item.dataId
            }

            updated_data = []

            for item in telemetria_data:
                if item.actionId == 17:
                    if item.dataId in actionid16_dict and not item.dataName:
                        item.dataName = actionid16_dict[item.dataId]
                    updated_data.append(item)

            return updated_data

        except Exception as e:
            logger.error(f"Error en dataStop: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=500):
        """
        Inserta los registros en MergedTelemetricStopCatchup en lotes de batch_size para optimizar la inserción.
        """
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricStopCatchup.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        Maneja la solicitud POST para actualizar los datos de MergedTelemetricStopCatchup.
        """
        try:
            merged_data = self.dataStop()

            if not merged_data:
                return Response({"message": "No hay datos para actualizar"}, status=status.HTTP_200_OK)

            id_maximo_registro = MergedTelemetricStopCatchup.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            registros_filtrados = [
                MergedTelemetricStopCatchup(**self.get_valid_fields(record.__dict__))
                for record in merged_data
                if record.recordId and record.recordId > id_maximo_registro
            ]

            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                self.bulk_insert_merged_data(registros_filtrados)

            return Response({"message": "Inserción exitosa"}, status=status.HTTP_200_OK)

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
            Maneja la solicitud GET para obtener todos los datos de MergedTelemetricStopCatchup.
            """
            try:
                # Obtiene todos los objetos de la tabla MergedTelemetricStopCatchup
                data = MergedTelemetricStopCatchup.objects.all()

                # Serializa los datos obtenidos utilizando el serializador correspondiente
                serializer = MergedTelemetricStopCatchupSerializer(data, many=True)

                return Response(serializer.data, status=status.HTTP_200_OK)

            except Exception as e:
                logger.error(f"Error en GET UpdateDataStopCatchup: {e}")
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

## actualización de los datos de catchup terminado
class UpdateDataEndCatchup(APIView):
    """
    API para actualizar y obtener los datos en la tabla MergedTelemetricEndCatchup
    fusionando registros de Telemetria.
    """

    @staticmethod
    def get_valid_fields(data):
        """
        Filtra los campos no válidos del diccionario `data` y devuelve un diccionario
        con solo los campos válidos del modelo MergedTelemetricEndCatchup.
        """
        valid_fields = {field.name for field in MergedTelemetricEndCatchup._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def dataEnd():
        """
        Fusiona solo el campo `dataName` para los registros de actionId=18
        que tienen el mismo `dataId` en los registros de actionId=16.
        """
        try:
            telemetria_data = Telemetria.objects.filter(actionId__in=[16, 18])

            actionid16_dict = {
                item.dataId: item.dataName
                for item in telemetria_data
                if item.actionId == 16 and item.dataId
            }

            updated_data = []

            for item in telemetria_data:
                if item.actionId == 18:
                    if item.dataId in actionid16_dict and not item.dataName:
                        item.dataName = actionid16_dict[item.dataId]
                    updated_data.append(item)

            return updated_data

        except Exception as e:
            logger.error(f"Error en dataEnd: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=500):
        """
        Inserta los registros en MergedTelemetricEndCatchup en lotes de batch_size para optimizar la inserción.
        """
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricEndCatchup.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        Maneja la solicitud POST para actualizar los datos de MergedTelemetricEndCatchup.
        """
        try:
            merged_data = self.dataEnd()

            if not merged_data:
                return Response({"message": "No hay datos para actualizar"}, status=status.HTTP_200_OK)

            id_maximo_registro = MergedTelemetricEndCatchup.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            registros_filtrados = [
                MergedTelemetricEndCatchup(**self.get_valid_fields(record.__dict__))
                for record in merged_data
                if record.recordId and record.recordId > id_maximo_registro
            ]

            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                self.bulk_insert_merged_data(registros_filtrados)

            return Response({"message": "Inserción exitosa"}, status=status.HTTP_200_OK)

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
        Maneja la solicitud GET para obtener todos los datos de MergedTelemetricEndCatchup.
        """
        try:
            # Obtiene todos los objetos de la tabla MergedTelemetricEndCatchup en la base de datos
            data = MergedTelemetricEndCatchup.objects.all()

            # Serializa los datos obtenidos utilizando el serializador correspondiente
            serializer = MergedTelemetricEndCatchupSerializer(data, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error en GET UpdateDataEndCatchup: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

## actualización de los datos de VOD pausados
class UpdateDataStopVOD(APIView):
    """
    API para actualizar y obtener los datos de la tabla MergedTelemetricStopVOD fusionando registros de Telemetria.
    """

    @staticmethod
    def get_valid_fields(data):
        """
        Filtra los campos no válidos del diccionario `data` y devuelve un diccionario
        con solo los campos válidos del modelo MergedTelemetricStopVOD.
        """
        valid_fields = {field.name for field in MergedTelemetricStopVOD._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def dataStop():
        """
        Fusiona solo el campo `dataName` para los registros de actionId=14
        que tienen el mismo `dataId` en los registros de actionId=13.
        """
        try:
            telemetria_data = Telemetria.objects.filter(actionId__in=[13, 14])

            actionid13_dict = {
                item.dataId: item.dataName
                for item in telemetria_data
                if item.actionId == 13 and item.dataId
            }

            updated_data = []

            for item in telemetria_data:
                if item.actionId == 14:
                    if item.dataId in actionid13_dict and not item.dataName:
                        item.dataName = actionid13_dict[item.dataId]
                    updated_data.append(item)

            return updated_data

        except Exception as e:
            logger.error(f"Error en dataStop: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=500):
        """
        Inserta los registros en MergedTelemetricStopVOD en lotes de batch_size para optimizar la inserción.
        """
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricStopVOD.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        Maneja la solicitud POST para actualizar los datos de MergedTelemetricStopVOD.
        """
        try:
            merged_data = self.dataStop()

            if not merged_data:
                return Response({"message": "No hay datos para actualizar"}, status=status.HTTP_200_OK)

            id_maximo_registro = MergedTelemetricStopVOD.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            registros_filtrados = [
                MergedTelemetricStopVOD(**self.get_valid_fields(record.__dict__))
                for record in merged_data
                if record.recordId and record.recordId > id_maximo_registro
            ]

            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                self.bulk_insert_merged_data(registros_filtrados)

            return Response({"message": "Inserción exitosa"}, status=status.HTTP_200_OK)

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
        Maneja la solicitud GET para obtener todos los datos de MergedTelemetricStopVOD.
        """
        try:
            # Obtiene todos los objetos de la tabla MergedTelemetricStopVOD en la base de datos
            data = MergedTelemetricStopVOD.objects.all()

            # Serializa los datos obtenidos utilizando el serializador correspondiente
            serializer = MergedTelemetricStopVODSerializer(data, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error en GET UpdateDataStopVOD: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ## actualización de los datos de VOD terminado
class UpdateDataEndVOD(APIView):
    """
    API para actualizar y obtener los datos de la tabla MergedTelemetricEndVOD fusionando registros de Telemetria.
    """

    @staticmethod
    def get_valid_fields(data):
        """
        Filtra los campos no válidos del diccionario `data` y devuelve un diccionario
        con solo los campos válidos del modelo MergedTelemetricEndVOD.
        """
        valid_fields = {field.name for field in MergedTelemetricEndVOD._meta.get_fields()}
        return {key: value for key, value in data.items() if key in valid_fields}

    @staticmethod
    def dataEnd():
        """
        Fusiona solo el campo `dataName` para los registros de actionId=15
        que tienen el mismo `dataId` en los registros de actionId=13.
        """
        try:
            telemetria_data = Telemetria.objects.filter(actionId__in=[13, 15])

            actionid13_dict = {
                item.dataId: item.dataName
                for item in telemetria_data
                if item.actionId == 13 and item.dataId
            }

            updated_data = []

            for item in telemetria_data:
                if item.actionId == 15:
                    if item.dataId in actionid13_dict and not item.dataName:
                        item.dataName = actionid13_dict[item.dataId]
                    updated_data.append(item)

            return updated_data

        except Exception as e:
            logger.error(f"Error en dataEnd: {e}")
            return []

    @staticmethod
    def bulk_insert_merged_data(records, batch_size=500):
        """
        Inserta los registros en MergedTelemetricEndVOD en lotes de batch_size para optimizar la inserción.
        """
        if records:
            for i in range(0, len(records), batch_size):
                batch = records[i:i + batch_size]
                MergedTelemetricEndVOD.objects.bulk_create(batch, ignore_conflicts=True)

    def post(self, request):
        """
        Maneja la solicitud POST para actualizar los datos de MergedTelemetricEndVOD.
        """
        try:
            merged_data = self.dataEnd()

            if not merged_data:
                return Response({"message": "No hay datos para actualizar"}, status=status.HTTP_200_OK)

            id_maximo_registro = MergedTelemetricEndVOD.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            registros_filtrados = [
                MergedTelemetricEndVOD(**self.get_valid_fields(record.__dict__))
                for record in merged_data
                if record.recordId and record.recordId > id_maximo_registro
            ]

            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                self.bulk_insert_merged_data(registros_filtrados)

            return Response({"message": "Inserción exitosa"}, status=status.HTTP_200_OK)

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
        Maneja la solicitud GET para obtener todos los datos de MergedTelemetricEndVOD.
        """
        try:
            # Obtiene todos los objetos de la tabla MergedTelemetricEndVOD en la base de datos
            data = MergedTelemetricEndVOD.objects.all()

            # Serializa los datos obtenidos utilizando el serializador correspondiente
            serializer = MergedTelemetricEndVODSerializer(data, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error en GET UpdateDataEndVOD: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TelemetriaDaysOTT(APIView):
    # permission_classes = [IsAuthenticated]
    @staticmethod
    def get_filtered_data(days):  # Añadido @staticmethod
        """
        Filtra los datos del modelo MergedTelemetricOTT según el rango de días proporcionado.
        """
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                return MergedTelemetricOTT.objects.filter(dataDate__range=[start_date, today])
            else:
                return MergedTelemetricOTT.objects.all()
        except Exception as e:
            raise ValueError(f"Error al filtrar los datos: {str(e)}")

    def dataRangeOTT(self, days):
        """
        Calcula la duración total de telemetría en horas para un rango de días específico.
        """
        try:
            # Usar self.get_filtered_data en lugar de get_filtered_data
            dataOTT = self.get_filtered_data(days)
            durationOTT = sum(item.dataDuration if item.dataDuration is not None else 0 for item in dataOTT) / 3600
            OTT = round(durationOTT, 2)
    
            today = datetime.now().date()
            start_date = today - timedelta(days=days) if days > 0 else None
    
            return {
                "duration": OTT,
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": today.isoformat()
            }
        except Exception as e:
            logger.error(f"Error en dataRangeOTT: {e}")
            return None

    def franjaHorarioOTT(self, days: int) -> Dict[str, Any]:
        """
        Calcula la duración de telemetría por franjas horarias y genera una gráfica de torta.

        Args:
            days (int): Número de días hacia atrás para calcular el rango de fechas.

        Returns:
            dict: Diccionario con los datos por franja horaria y el gráfico en formato base64.
        """
        if days <= 0:
            raise ValueError("El número de días debe ser mayor a 0.")

        try:
            # Obtener los datos de telemetría filtrados
            dataOTT = self.get_filtered_data(days)

            # Validar que dataOTT no esté vacío
            if not dataOTT:
                return {"error": "No se encontraron datos en el rango especificado."}

            # Definir franjas horarias
            data_duration_by_franja = defaultdict(float)
            franjas = {
                "Madrugada": (0, 5),
                "Mañana": (5, 12),
                "Tarde": (12, 18),
                "Noche": (18, 24)
            }

            # Calcular duración por franja horaria
            for item in dataOTT:
                hora = item.timeDate
                for franja, (inicio, fin) in franjas.items():
                    if inicio <= hora < fin:
                        data_duration_by_franja[franja] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los valores
            data_duration_by_franja = {franja: round(duration, 2) for franja, duration in data_duration_by_franja.items()}

            # Generar la gráfica de torta
            labels = list(data_duration_by_franja.keys())
            sizes = list(data_duration_by_franja.values())
            colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']  # Colores para las secciones de la torta

            # Función personalizada para mostrar porcentaje y valor
            def autopct_func(pct, all_vals):
                absolute = int(round(pct / 100. * sum(all_vals), 2))
                return f"{pct:.1f}%\n({absolute} h)"

            plt.figure(figsize=(6, 6))
            plt.pie(sizes, labels=labels, 
                    autopct=lambda pct: autopct_func(pct, sizes), 
                    startangle=140, 
                    colors=colors)
            plt.title('Distribución de Duración por Franja Horaria')

            # Guardar la gráfica en un buffer
            buf = io.BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            encoded_image = base64.b64encode(buf.getvalue()).decode('utf-8')
            buf.close()
            plt.close()

            # Retornar los datos y la gráfica
            return {
                "data": data_duration_by_franja,
                "chart": encoded_image  # Imagen codificada en base64
            }

        except ValueError as ve:
            print(f"Error de validación: {ve}")
            return {"error": str(ve)}
        except Exception as e:
            print(f"Ocurrió un error durante la generación de la gráfica: {e}")
            return {"error": "Error interno del servidor."}

    def listEventOTT(self, days):
         """
         Calcula la duración total por cada evento (dataName) en horas para un rango de días específico.
         """
         try:
             dataOTT = self.get_filtered_data(days)

             # Diccionario para almacenar la suma de dataDuration para cada dataName
             data_duration_by_name = defaultdict(float)

             for item in dataOTT:
                 # Suma dataDuration para cada dataName
                 data_duration_by_name[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

             rounded_data = {data_name: round(duration, 2) for data_name, duration in data_duration_by_name.items()}

             return rounded_data

         except ValidationError as e:
             print(f"Error de validación durante la consulta a la base de datos: {e}")
             return None
         except Exception as e:
             print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
             return None

    def listCountEventOTT(self, days):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en un rango de días específico.
        """
        try:
            dataOTT = self.get_filtered_data(days)

            ott = {}
            for item in dataOTT:
                event = item.dataName
                ott[event] = ott.get(event, 0) + 1

            return ott

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def graphOTT(self, days):
        """
        Genera una gráfica interactiva con Plotly para comparar horas vistas y número de veces vistas por canal.
        Organiza los datos en orden descendente según las horas vistas.
        Args:
        days (int): Número de días para filtrar los datos.
        Returns:
        dict: JSON de la gráfica interactiva.
        """
        if days < 0:
            raise ValueError("El número de días debe ser mayor a 0.")
        try:
            # Obtener los datos
            hours_data = self.listEventOTT(days)
            count_data = self.listCountEventOTT(days)
    
            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_channels = sorted(hours_data.keys(), key=lambda x: hours_data[x], reverse=True)
    
            # Reorganizar los datos según el orden de sorted_channels
            hours = [hours_data[channel] for channel in sorted_channels]
            counts = [count_data.get(channel, 0) for channel in sorted_channels]
    
            # Crear figura
            fig = go.Figure()
    
            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))
    
            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=counts,
                mode='lines+markers',
                name='Veces Vistas',
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))
    
            # Configurar diseño
            fig.update_layout(
                title='Comparativa de Horas vs Veces Vistas por Canal',
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                xaxis=dict(
                    tickangle=45,
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,  # Aumentar la altura del gráfico
                margin=dict(b=100)  # Aumentar el margen inferior para las etiquetas
            )
    
            # Convertir la figura a JSON
            graph_json = fig.to_json()
            return {"graph": graph_json}
        except Exception as e:
            return {"error": str(e)}

    def franjaHorarioEventOTTMadrugada(self, days):
        """
        Calcula la duración de telemetría para eventos en la franja horaria de madrugada (00:00 a 05:00).
        """
        try:
            dataOTT = self.get_filtered_data(days)

            # Diccionario para almacenar la duración por tipo de evento
            data_duration_by_event = defaultdict(float)

            # Filtrar eventos en la madrugada y sumar la duración
            for item in dataOTT:
                if 0 <= item.timeDate < 5:  # Franja horaria de la madrugada
                    data_duration_by_event[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los resultados
            result = {data_name: round(duration, 2) for data_name, duration in data_duration_by_event.items()}
            return result

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def listCountEventOTTMadrugada(self, days):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en la franja horaria de madrugada (00:00 a 05:00).
        """
        try:
            dataOTT = self.get_filtered_data(days)

            # Diccionario para almacenar el conteo de eventos
            ott_madrugada = defaultdict(int)

            # Filtrar eventos en la madrugada y contar
            for item in dataOTT:
                if 0 <= item.timeDate < 5:
                    ott_madrugada[item.dataName] += 1

            return dict(ott_madrugada)

        except Exception as e:
            print(f"Error: {e}")
            return None

    def graphOTTMadrugada(self, days):
        """
        Genera una gráfica de barras y líneas para comparar horas vistas y número de veces vistas por canal (madrugada).
        """
        if days < 0:
            raise ValueError("El número de días debe ser mayor a 0.")
        try:
            # Obtener los datos
            hours_data = self.franjaHorarioEventOTTMadrugada(days)
            count_data = self.listCountEventOTTMadrugada(days)

            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_channels = sorted(hours_data.keys(), key=lambda x: hours_data[x], reverse=True)

            # Reorganizar los datos según el orden de sorted_channels
            hours = [hours_data[channel] for channel in sorted_channels]
            counts = [count_data.get(channel, 0) for channel in sorted_channels]

            # Crear figura
            fig = go.Figure()

            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))

            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=counts,
                mode='lines+markers',
                name='Veces Vistas',
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))

            # Configurar diseño
            fig.update_layout(
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                xaxis=dict(
                    tickangle=45,
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,  # Aumentar la altura del gráfico
                margin=dict(b=100)  # Aumentar el margen inferior para las etiquetas
            )
    
            # Convertir la figura a JSON
            graph_json = fig.to_json()
            return {"graph": graph_json}
        except Exception as e:
            return {"error": str(e)}

    def listCountEventOTTMañana(self, days):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en la franja horaria de la mañana (05:00 a 12:00).
        """
        try:
            # Obtener los datos filtrados por el rango de días
            dataOTT = self.get_filtered_data(days)

            # Diccionario para almacenar el conteo de eventos en la mañana
            ott_mañana = defaultdict(int)

            # Filtrar y contar eventos en la franja de la mañana
            for item in dataOTT:
                if 5 <= item.timeDate < 12:  # Verificar si la hora está en la franja de la mañana
                    ott_mañana[item.dataName] += 1  # Incrementar el contador

            return dict(ott_mañana)  # Convertir a diccionario estándar antes de devolver

        except Exception as e:
            # Manejar errores
            return {"error": str(e)}

    def franjaHorarioEventOTTMañana(self, days):
        """
        Calcula la duración total de telemetría para eventos en la franja de la mañana (05:00 a 12:00).
        """
        try:
            dataOTT = self.get_filtered_data(days)

            # Diccionario para almacenar la duración por tipo de evento
            data_duration_by_event = defaultdict(float)

            # Filtrar eventos en la mañana y sumar la duración
            for item in dataOTT:
                if 5 <= item.timeDate < 12:  # Franja de la mañana
                    data_duration_by_event[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los resultados
            result = {data_name: round(duration, 2) for data_name, duration in data_duration_by_event.items()}
            return result

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def graphOTTMañana(self, days):
        """
        Genera un gráfico combinado (barras y líneas) para la franja de la mañana (05:00 a 12:00).
        """
        if days < 0:
            raise ValueError("El número de días debe ser mayor a 0.")
        try:
            # Obtener los datos
            hours_data = self.franjaHorarioEventOTTMañana(days)  # {dataName: horas}
            count_data = self.listCountEventOTTMañana(days)  # {dataName: conteo}

            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_channels = sorted(hours_data.keys(), key=lambda x: hours_data[x], reverse=True)
    
            # Reorganizar los datos según el orden de sorted_channels
            hours = [hours_data[channel] for channel in sorted_channels]
            counts = [count_data.get(channel, 0) for channel in sorted_channels]
    
            # Crear figura
            fig = go.Figure()
    
            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))
    
            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=counts,
                mode='lines+markers',
                name='Veces Vistas',
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))
    
            # Configurar diseño
            fig.update_layout(
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                xaxis=dict(
                    tickangle=45,
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,  # Aumentar la altura del gráfico
                margin=dict(b=100)  # Aumentar el margen inferior para las etiquetas
            )
    
            # Convertir la figura a JSON
            graph_json = fig.to_json()
            return {"graph": graph_json}
        except Exception as e:
            return {"error": str(e)}

    def franjaHorarioEventOTTTarde(self, days):
        """
        Calcula la duración total de telemetría para eventos en la franja de la tarde (12:00 a 18:00).
        """
        try:
            dataOTT = self.get_filtered_data(days)

            # Diccionario para almacenar la duración por tipo de evento
            data_duration_by_event = defaultdict(float)

            # Filtrar eventos en la tarde y sumar la duración
            for item in dataOTT:
                if 12 <= item.timeDate < 18:  # Franja de la tarde
                    data_duration_by_event[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los resultados
            result = {data_name: round(duration, 2) for data_name, duration in data_duration_by_event.items()}
            return result

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def listCountEventOTTTarde(self, days):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en la franja horaria de la tarde (12:00 a 18:00).
        """
        try:
            # Obtener los datos filtrados por el rango de días
            dataOTT = self.get_filtered_data(days)

            # Diccionario para almacenar el conteo de eventos en la tarde
            ott_tarde = defaultdict(int)

            # Filtrar eventos en la tarde y contar
            for item in dataOTT:
                if 12 <= item.timeDate < 18:  # Verificar si la hora está en la franja de la tarde
                    ott_tarde[item.dataName] += 1

            return dict(ott_tarde)  # Convertir a diccionario estándar antes de devolver

        except Exception as e:
            print(f"Error: {e}")
            return None

    def graphOTTTarde(self, days):
        """
        Genera un gráfico combinado (barras y líneas) para la franja de la tarde (12:00 a 18:00).
        """
        if days < 0:
            raise ValueError("El número de días debe ser mayor a 0.")
        try:
            # Obtener los datos
            hours_data = self.franjaHorarioEventOTTTarde(days)  # {dataName: horas}
            count_data = self.listCountEventOTTTarde(days)  # {dataName: conteo}

            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_channels = sorted(hours_data.keys(), key=lambda x: hours_data[x], reverse=True)
    
            # Reorganizar los datos según el orden de sorted_channels
            hours = [hours_data[channel] for channel in sorted_channels]
            counts = [count_data.get(channel, 0) for channel in sorted_channels]
    
            # Crear figura
            fig = go.Figure()
    
            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))
    
            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=counts,
                mode='lines+markers',
                name='Veces Vistas',
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))
    
            # Configurar diseño
            fig.update_layout(
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                xaxis=dict(
                    tickangle=45,
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,  # Aumentar la altura del gráfico
                margin=dict(b=100)  # Aumentar el margen inferior para las etiquetas
            )
    
            # Convertir la figura a JSON
            graph_json = fig.to_json()
            return {"graph": graph_json}
        except Exception as e:
            return {"error": str(e)}

    def franjaHorarioEventOTTNoche(self, days):
        """
        Calcula la duración total de telemetría para eventos en la franja de la noche (18:00 a 24:00).
        """
        try:
            dataOTT = self.get_filtered_data(days)

            # Diccionario para almacenar la duración por tipo de evento
            data_duration_by_event = defaultdict(float)

            # Filtrar eventos en la noche y sumar la duración
            for item in dataOTT:
                if 18 <= item.timeDate < 24:  # Franja de la noche
                    data_duration_by_event[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los resultados
            result = {data_name: round(duration, 2) for data_name, duration in data_duration_by_event.items()}
            return result

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def listCountEventOTTNoche(self, days):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en la franja horaria de la noche (18:00 a 24:00).
        """
        try:
            # Obtener los datos filtrados por el rango de días
            dataOTT = self.get_filtered_data(days)

            # Diccionario para almacenar el conteo de eventos en la noche
            ott_noche = defaultdict(int)

            # Filtrar eventos en la noche y contar
            for item in dataOTT:
                if 18 <= item.timeDate < 24:  # Verificar si la hora está en la franja de la noche
                    ott_noche[item.dataName] += 1

            return dict(ott_noche)  # Convertir a diccionario estándar antes de devolver

        except Exception as e:
            print(f"Error: {e}")
            return None

    def graphOTTNoche(self, days):
        """
        Genera un gráfico combinado (barras y líneas) para la franja de la noche (18:00 a 24:00),
        ordenando los canales de mayor a menor según las horas vistas y mostrando las horas vistas sobre las barras.
        """
        if days < 0:
            raise ValueError("El número de días debe ser mayor a 0.")
        try:
            # Obtener los datos
            hours_data = self.franjaHorarioEventOTTNoche(days)  # {dataName: horas}
            count_data = self.listCountEventOTTNoche(days)  # {dataName: conteo}

            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_data = sorted(hours_data.items(), key=lambda x: x[1], reverse=True)
            sorted_channels = [item[0] for item in sorted_data]  # Extraer nombres de canales
            sorted_hours = [item[1] for item in sorted_data]  # Extraer horas vistas
            sorted_counts = [count_data.get(channel, 0) for channel in sorted_channels]  # Ordenar conteos

            # Crear figura
            fig = go.Figure()

            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=sorted_hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                text=[f"{hours:.2f}" for hours in sorted_hours],  # Mostrar las horas vistas sobre las barras
                textposition='outside',
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))

            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=sorted_counts,
                mode='lines+markers+text',
                name='Veces Vistas',
                text=[f"{count}" for count in sorted_counts],
                textposition="top center",
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))

            # Configurar diseño
            fig.update_layout(
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,
                margin=dict(b=150),
                xaxis=dict(
                    tickangle=45,  # Rotar etiquetas
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                )
            )

            # Mostrar valores en la escala logarítmica solo si hay datos pequeños
            if min(sorted_hours) > 0:
                fig.update_layout(
                    yaxis=dict(
                        type="log",  # Escala logarítmica
                        showgrid=True,
                        titlefont=dict(color="pink")
                    )
                )

            return {"graph": fig.to_json()}
        except Exception as e:
            print(f"Error: {e}")
            return {"error": str(e)}

    def get(self, request, days=None):
        try:
            # Obtener los datos
            durationOTT = self.dataRangeOTT(days)
            franjaHorarioOOT = self.franjaHorarioOTT(days)

            ottEvents = self.listEventOTT(days)
            listCountEventOTT = self.listCountEventOTT(days)
            graphOTT = self.graphOTT(days)

            graphOTTMadrugada = self.graphOTTMadrugada(days)
            franjahorariaEventsOTTMadrugada = self.franjaHorarioEventOTTMadrugada(days)
            countChannelsMadrugada = self.listCountEventOTTMadrugada(days)

            graphOTTMañana = self.graphOTTMañana(days)
            franjahorariaEventsOTTMañana = self.franjaHorarioEventOTTMañana(days)
            countChannelsMañana = self.listCountEventOTTMañana(days)

            graphOTTTarde = self.graphOTTTarde(days)
            franjahorariaEventsOTTTarde = self.franjaHorarioEventOTTTarde(days)
            countChannelsTarde = self.listCountEventOTTTarde(days)

            graphOTTNoche = self.graphOTTNoche(days)
            franjahorariaEventsOTTNoche = self.franjaHorarioEventOTTNoche(days)
            countChannelsNoche = self.listCountEventOTTNoche(days)
            return Response(
                {
                    "totals": {
                        "franjahorariaeventottmadrugada": franjahorariaEventsOTTMadrugada,
                        "countchannelsmadrugada": countChannelsMadrugada,
                        "franjahorariaeventottmañana": franjahorariaEventsOTTMañana,
                        "countchannelsmañana": countChannelsMañana,
                        "franjahorariaeventotttarde": franjahorariaEventsOTTTarde,
                        "countchannelstarde": countChannelsTarde,
                        "franjahorariaeventottnoche": franjahorariaEventsOTTNoche,
                        "countchannelsnoche": countChannelsNoche,
                        "totaldurationott": durationOTT,
                        "franjahorariaott": franjaHorarioOOT,
                    },
                    "events": {
                        "listOTT": ottEvents,
                        "listCountEventOTT": listCountEventOTT,
                    },
                    "graphs": {
                        "graphott": graphOTT,
                        "graphottMadrugada": graphOTTMadrugada,
                        "graphottMañana": graphOTTMañana,
                        "graphottTarde": graphOTTTarde,
                        "graphottNoche": graphOTTNoche,
                    },
                },
                status=status.HTTP_200_OK
            )
        except ValueError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except KeyError as ke:
            return Response({"error": f"Clave no encontrada: {ke}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Error interno: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TelemetriaDateOTT(APIView):
    @staticmethod
    def get_filtered_data(start_date, end_date):
        """
        Filtra los datos del modelo MergedTelemetricOTT según el rango de dias proporcionado.
        """
        try:
            # Asegurarse de que las fechas estén en el orden correcto
            start_date, end_date = sorted([start_date, end_date])
            
            # Filtrar los datos por rango de fechas
            return MergedTelemetricOTT.objects.filter(dataDate__range=[start_date, end_date])
        except ValueError as e:
            raise ValueError(f"Error al filtrar los datos: {str(e)}")

    def dataDateRangeOTT(self, start_date, end_date):
        """
        Calcula la duración total de telemetría para un rango de fechas específico.
        """
        try:
            # Filtrar los datos por rango de fechas
            dataOTT = self.get_filtered_data(start_date, end_date)
            durationOTT = sum(item.dataDuration if item.dataDuration is not None else 0 for item in dataOTT) / 3600
            OTT = round(durationOTT, 2)
            return {
                "duration": OTT,
                "start_date": start_date,
                "end_date": end_date
            }
        except Exception as e:
            logger.error(f"Error en dataRangeOTT: {e}")
            return None

    def dateFranjaHorarioOTT(self, start_date, end_date) -> Dict[str, Any]:
        """
        Calcula la duración de telemetría por franjas horarias y genera una gráfica de torta.

        Args:
            days (int): Número de días hacia atrás para calcular el rango de fechas.

        Returns:
            dict: Diccionario con los datos por franja horaria y el gráfico en formato base64.
        """

        try:
            # Obtener los datos de telemetría filtrados
            dataOTT = self.get_filtered_data(start_date, end_date)

            # Validar que dataOTT no esté vacío
            if not dataOTT:
                return {"error": "No se encontraron datos en el rango especificado."}

            # Definir franjas horarias
            data_duration_by_franja = defaultdict(float)
            franjas = {
                "Madrugada": (0, 5),
                "Mañana": (5, 12),
                "Tarde": (12, 18),
                "Noche": (18, 24)
            }

            # Calcular duración por franja horaria
            for item in dataOTT:
                hora = item.timeDate
                for franja, (inicio, fin) in franjas.items():
                    if inicio <= hora < fin:
                        data_duration_by_franja[franja] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los valores
            data_duration_by_franja = {franja: round(duration, 2) for franja, duration in data_duration_by_franja.items()}

            # Generar la gráfica de torta
            labels = list(data_duration_by_franja.keys())
            sizes = list(data_duration_by_franja.values())
            colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']  # Colores para las secciones de la torta

            # Función personalizada para mostrar porcentaje y valor
            def autopct_func(pct, all_vals):
                absolute = int(round(pct / 100. * sum(all_vals), 2))
                return f"{pct:.1f}%\n({absolute} h)"

            plt.figure(figsize=(6, 6))
            plt.pie(sizes, labels=labels, 
                    autopct=lambda pct: autopct_func(pct, sizes), 
                    startangle=140, 
                    colors=colors)
            plt.title('Distribución de Duración por Franja Horaria')

            # Guardar la gráfica en un buffer
            buf = io.BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            encoded_image = base64.b64encode(buf.getvalue()).decode('utf-8')
            buf.close()
            plt.close()

            # Retornar los datos y la gráfica
            return {
                "data": data_duration_by_franja,
                "chart": encoded_image  # Imagen codificada en base64
            }

        except ValueError as ve:
            print(f"Error de validación: {ve}")
            return {"error": str(ve)}
        except Exception as e:
            print(f"Ocurrió un error durante la generación de la gráfica: {e}")
            return {"error": "Error interno del servidor."}

    def listEventOTT(self, start_date, end_date):
         """
         Calcula la duración total por cada evento (dataName) en horas para un rango de días específico.
         """
         try:
             dataOTT = self.get_filtered_data(start_date, end_date)

             # Diccionario para almacenar la suma de dataDuration para cada dataName
             data_duration_by_name = defaultdict(float)

             for item in dataOTT:
                 # Suma dataDuration para cada dataName
                 data_duration_by_name[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

             rounded_data = {data_name: round(duration, 2) for data_name, duration in data_duration_by_name.items()}

             return rounded_data

         except ValidationError as e:
             print(f"Error de validación durante la consulta a la base de datos: {e}")
             return None
         except Exception as e:
             print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
             return None

    def listCountEventOTT(self, start_date, end_date):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en un rango de días específico.
        """
        try:
            dataOTT = self.get_filtered_data(start_date, end_date)

            ott = {}
            for item in dataOTT:
                event = item.dataName
                ott[event] = ott.get(event, 0) + 1

            return ott

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def graphOTT(self, start_date, end_date):
        """
        Genera una gráfica interactiva con Plotly para comparar horas vistas y número de veces vistas por canal.
        Organiza los datos en orden descendente según las horas vistas.
        Args:
        days (int): Número de días para filtrar los datos.
        Returns:
        dict: JSON de la gráfica interactiva.
        """
        try:
            # Obtener los datos
            hours_data = self.listEventOTT(start_date, end_date)
            count_data = self.listCountEventOTT(start_date, end_date)
    
            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_channels = sorted(hours_data.keys(), key=lambda x: hours_data[x], reverse=True)
    
            # Reorganizar los datos según el orden de sorted_channels
            hours = [hours_data[channel] for channel in sorted_channels]
            counts = [count_data.get(channel, 0) for channel in sorted_channels]
    
            # Crear figura
            fig = go.Figure()
    
            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))
    
            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=counts,
                mode='lines+markers',
                name='Veces Vistas',
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))
    
            # Configurar diseño
            fig.update_layout(
                title='Comparativa de Horas vs Veces Vistas por Canal',
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                xaxis=dict(
                    tickangle=45,
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,  # Aumentar la altura del gráfico
                margin=dict(b=100)  # Aumentar el margen inferior para las etiquetas
            )
    
            # Convertir la figura a JSON
            graph_json = fig.to_json()
            return {"graph": graph_json}
        except Exception as e:
            return {"error": str(e)}

    def franjaHorarioEventOTTMadrugada(self, start_date, end_date):
        """
        Calcula la duración de telemetría para eventos en la franja horaria de madrugada (00:00 a 05:00).
        """
        try:
            dataOTT = self.get_filtered_data(start_date, end_date)

            # Diccionario para almacenar la duración por tipo de evento
            data_duration_by_event = defaultdict(float)

            # Filtrar eventos en la madrugada y sumar la duración
            for item in dataOTT:
                if 0 <= item.timeDate < 5:  # Franja horaria de la madrugada
                    data_duration_by_event[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los resultados
            result = {data_name: round(duration, 2) for data_name, duration in data_duration_by_event.items()}
            return result

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def listCountEventOTTMadrugada(self, start_date, end_date):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en la franja horaria de madrugada (00:00 a 05:00).
        """
        try:
            dataOTT = self.get_filtered_data(start_date, end_date)

            # Diccionario para almacenar el conteo de eventos
            ott_madrugada = defaultdict(int)

            # Filtrar eventos en la madrugada y contar
            for item in dataOTT:
                if 0 <= item.timeDate < 5:
                    ott_madrugada[item.dataName] += 1

            return dict(ott_madrugada)

        except Exception as e:
            print(f"Error: {e}")
            return None

    def graphOTTMadrugada(self, start_date, end_date):
        """
        Genera una gráfica de barras y líneas para comparar horas vistas y número de veces vistas por canal (madrugada).
        """

        try:
            # Obtener los datos
            hours_data = self.franjaHorarioEventOTTMadrugada(start_date, end_date)
            count_data = self.listCountEventOTTMadrugada(start_date, end_date)

            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_channels = sorted(hours_data.keys(), key=lambda x: hours_data[x], reverse=True)

            # Reorganizar los datos según el orden de sorted_channels
            hours = [hours_data[channel] for channel in sorted_channels]
            counts = [count_data.get(channel, 0) for channel in sorted_channels]

            # Crear figura
            fig = go.Figure()

            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))

            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=counts,
                mode='lines+markers',
                name='Veces Vistas',
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))

            # Configurar diseño
            fig.update_layout(
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                xaxis=dict(
                    tickangle=45,
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,  # Aumentar la altura del gráfico
                margin=dict(b=100)  # Aumentar el margen inferior para las etiquetas
            )
    
            # Convertir la figura a JSON
            graph_json = fig.to_json()
            return {"graph": graph_json}
        except Exception as e:
            return {"error": str(e)}

    def listCountEventOTTMañana(self, start_date, end_date):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en la franja horaria de la mañana (05:00 a 12:00).
        """
        try:
            # Obtener los datos filtrados por el rango de días
            dataOTT = self.get_filtered_data(start_date, end_date)

            # Diccionario para almacenar el conteo de eventos en la mañana
            ott_mañana = defaultdict(int)

            # Filtrar y contar eventos en la franja de la mañana
            for item in dataOTT:
                if 5 <= item.timeDate < 12:  # Verificar si la hora está en la franja de la mañana
                    ott_mañana[item.dataName] += 1  # Incrementar el contador

            return dict(ott_mañana)  # Convertir a diccionario estándar antes de devolver

        except Exception as e:
            # Manejar errores
            return {"error": str(e)}

    def franjaHorarioEventOTTMañana(self, start_date, end_date):
        """
        Calcula la duración total de telemetría para eventos en la franja de la mañana (05:00 a 12:00).
        """
        try:
            dataOTT = self.get_filtered_data(start_date, end_date)

            # Diccionario para almacenar la duración por tipo de evento
            data_duration_by_event = defaultdict(float)

            # Filtrar eventos en la mañana y sumar la duración
            for item in dataOTT:
                if 5 <= item.timeDate < 12:  # Franja de la mañana
                    data_duration_by_event[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los resultados
            result = {data_name: round(duration, 2) for data_name, duration in data_duration_by_event.items()}
            return result

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def graphOTTMañana(self, start_date, end_date):
        """
        Genera un gráfico combinado (barras y líneas) para la franja de la mañana (05:00 a 12:00).
        """

        try:
            # Obtener los datos
            hours_data = self.franjaHorarioEventOTTMañana(start_date, end_date)  # {dataName: horas}
            count_data = self.listCountEventOTTMañana(start_date, end_date)  # {dataName: conteo}

            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_channels = sorted(hours_data.keys(), key=lambda x: hours_data[x], reverse=True)
    
            # Reorganizar los datos según el orden de sorted_channels
            hours = [hours_data[channel] for channel in sorted_channels]
            counts = [count_data.get(channel, 0) for channel in sorted_channels]
    
            # Crear figura
            fig = go.Figure()
    
            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))
    
            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=counts,
                mode='lines+markers',
                name='Veces Vistas',
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))
    
            # Configurar diseño
            fig.update_layout(
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                xaxis=dict(
                    tickangle=45,
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,  # Aumentar la altura del gráfico
                margin=dict(b=100)  # Aumentar el margen inferior para las etiquetas
            )
    
            # Convertir la figura a JSON
            graph_json = fig.to_json()
            return {"graph": graph_json}
        except Exception as e:
            return {"error": str(e)}

    def franjaHorarioEventOTTTarde(self, start_date, end_date):
        """
        Calcula la duración total de telemetría para eventos en la franja de la tarde (12:00 a 18:00).
        """
        try:
            dataOTT = self.get_filtered_data(start_date, end_date)

            # Diccionario para almacenar la duración por tipo de evento
            data_duration_by_event = defaultdict(float)

            # Filtrar eventos en la tarde y sumar la duración
            for item in dataOTT:
                if 12 <= item.timeDate < 18:  # Franja de la tarde
                    data_duration_by_event[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los resultados
            result = {data_name: round(duration, 2) for data_name, duration in data_duration_by_event.items()}
            return result

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def listCountEventOTTTarde(self, start_date, end_date):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en la franja horaria de la tarde (12:00 a 18:00).
        """
        try:
            # Obtener los datos filtrados por el rango de días
            dataOTT = self.get_filtered_data(start_date, end_date)

            # Diccionario para almacenar el conteo de eventos en la tarde
            ott_tarde = defaultdict(int)

            # Filtrar eventos en la tarde y contar
            for item in dataOTT:
                if 12 <= item.timeDate < 18:  # Verificar si la hora está en la franja de la tarde
                    ott_tarde[item.dataName] += 1

            return dict(ott_tarde)  # Convertir a diccionario estándar antes de devolver

        except Exception as e:
            print(f"Error: {e}")
            return None

    def graphOTTTarde(self, start_date, end_date):
        """
        Genera un gráfico combinado (barras y líneas) para la franja de la tarde (12:00 a 18:00).
        """
        
        try:
            # Obtener los datos
            hours_data = self.franjaHorarioEventOTTTarde(start_date, end_date)  # {dataName: horas}
            count_data = self.listCountEventOTTTarde(start_date, end_date)  # {dataName: conteo}

            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_channels = sorted(hours_data.keys(), key=lambda x: hours_data[x], reverse=True)
    
            # Reorganizar los datos según el orden de sorted_channels
            hours = [hours_data[channel] for channel in sorted_channels]
            counts = [count_data.get(channel, 0) for channel in sorted_channels]
    
            # Crear figura
            fig = go.Figure()
    
            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))
    
            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=counts,
                mode='lines+markers',
                name='Veces Vistas',
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))
    
            # Configurar diseño
            fig.update_layout(
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                xaxis=dict(
                    tickangle=45,
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,  # Aumentar la altura del gráfico
                margin=dict(b=100)  # Aumentar el margen inferior para las etiquetas
            )
    
            # Convertir la figura a JSON
            graph_json = fig.to_json()
            return {"graph": graph_json}
        except Exception as e:
            return {"error": str(e)}

    def franjaHorarioEventOTTNoche(self, start_date, end_date):
        """
        Calcula la duración total de telemetría para eventos en la franja de la noche (18:00 a 24:00).
        """
        try:
            dataOTT = self.get_filtered_data(start_date, end_date)

            # Diccionario para almacenar la duración por tipo de evento
            data_duration_by_event = defaultdict(float)

            # Filtrar eventos en la noche y sumar la duración
            for item in dataOTT:
                if 18 <= item.timeDate < 24:  # Franja de la noche
                    data_duration_by_event[item.dataName] += item.dataDuration / 3600 if item.dataDuration else 0

            # Redondear los resultados
            result = {data_name: round(duration, 2) for data_name, duration in data_duration_by_event.items()}
            return result

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def listCountEventOTTNoche(self, start_date, end_date):
        """
        Cuenta la cantidad de eventos por tipo (dataName) en la franja horaria de la noche (18:00 a 24:00).
        """
        try:
            # Obtener los datos filtrados por el rango de días
            dataOTT = self.get_filtered_data(start_date, end_date)

            # Diccionario para almacenar el conteo de eventos en la noche
            ott_noche = defaultdict(int)

            # Filtrar eventos en la noche y contar
            for item in dataOTT:
                if 18 <= item.timeDate < 24:  # Verificar si la hora está en la franja de la noche
                    ott_noche[item.dataName] += 1

            return dict(ott_noche)  # Convertir a diccionario estándar antes de devolver

        except Exception as e:
            print(f"Error: {e}")
            return None

    def graphOTTNoche(self, start_date, end_date):
        """
        Genera un gráfico combinado (barras y líneas) para la franja de la noche (18:00 a 24:00),
        ordenando los canales de mayor a menor según las horas vistas y mostrando las horas vistas sobre las barras.
        """
        try:
            # Obtener los datos
            hours_data = self.franjaHorarioEventOTTNoche(start_date, end_date)  # {dataName: horas}
            count_data = self.listCountEventOTTNoche(start_date, end_date)  # {dataName: conteo}

            # Crear una lista de canales ordenada por horas vistas (descendente)
            sorted_data = sorted(hours_data.items(), key=lambda x: x[1], reverse=True)
            sorted_channels = [item[0] for item in sorted_data]  # Extraer nombres de canales
            sorted_hours = [item[1] for item in sorted_data]  # Extraer horas vistas
            sorted_counts = [count_data.get(channel, 0) for channel in sorted_channels]  # Ordenar conteos

            # Crear figura
            fig = go.Figure()

            # Agregar barras para las horas vistas
            fig.add_trace(go.Bar(
                x=sorted_channels,
                y=sorted_hours,
                name='Horas Vistas',
                marker_color='pink',
                opacity=0.7,
                text=[f"{hours:.2f}" for hours in sorted_hours],  # Mostrar las horas vistas sobre las barras
                textposition='outside',
                hovertemplate='<b>Canal:</b> %{x}<br><b>Horas:</b> %{y:.2f}<extra></extra>'
            ))

            # Agregar línea para las veces vistas
            fig.add_trace(go.Scatter(
                x=sorted_channels,
                y=sorted_counts,
                mode='lines+markers+text',
                name='Veces Vistas',
                text=[f"{count}" for count in sorted_counts],
                textposition="top center",
                marker=dict(color='blue', size=8),
                line=dict(width=2),
                hovertemplate='<b>Canal:</b> %{x}<br><b>Veces Vistas:</b> %{y}<extra></extra>'
            ))

            # Configurar diseño
            fig.update_layout(
                xaxis_title='Canales',
                yaxis=dict(
                    title=dict(
                        text='Horas Vistas',
                        font=dict(color='pink')  # ✅ Corrección: titlefont → title.font
                    ),
                    type='log',  
                    showgrid=True
                ),
                yaxis2=dict(
                    title=dict(
                        text='Veces Vistas',
                        font=dict(color='blue')  # ✅ Corrección: titlefont → title.font
                    ),
                    overlaying='y',
                    side='right',
                    type='log'  
                ),
                template='plotly_white',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                height=600,
                margin=dict(b=150),
                xaxis=dict(
                    tickangle=45,  # Rotar etiquetas
                    tickmode='array',
                    tickvals=list(range(len(sorted_channels))),
                    ticktext=sorted_channels
                )
            )

            # Mostrar valores en la escala logarítmica solo si hay datos pequeños
            if min(sorted_hours) > 0:
                fig.update_layout(
                    yaxis=dict(
                        type="log",  # Escala logarítmica
                        showgrid=True,
                        titlefont=dict(color="pink")
                    )
                )

            return {"graph": fig.to_json()}
        except Exception as e:
            print(f"Error: {e}")
            return {"error": str(e)}


    def get(self, request, start, end):
        try:
            # Convertir las fechas de la URL a objetos datetime
            start_date = datetime.strptime(start, "%Y-%m-%d")
            end_date = datetime.strptime(end, "%Y-%m-%d")

            # Obtener los datos
            durationOTT = self.dataDateRangeOTT(start_date, end_date)
            franjaHorarioOOT = self.dateFranjaHorarioOTT(start_date, end_date)

            ottEvents = self.listEventOTT(start_date, end_date)
            listCountEventOTT = self.listCountEventOTT(start_date, end_date)
            graphOTT = self.graphOTT(start_date, end_date)

            graphOTTMadrugada = self.graphOTTMadrugada(start_date, end_date)
            franjahorariaEventsOTTMadrugada = self.franjaHorarioEventOTTMadrugada(start_date, end_date)
            countChannelsMadrugada = self.listCountEventOTTMadrugada(start_date, end_date)

            graphOTTMañana = self.graphOTTMañana(start_date, end_date)
            franjahorariaEventsOTTMañana = self.franjaHorarioEventOTTMañana(start_date, end_date)
            countChannelsMañana = self.listCountEventOTTMañana(start_date, end_date)

            graphOTTTarde = self.graphOTTTarde(start_date, end_date)
            franjahorariaEventsOTTTarde = self.franjaHorarioEventOTTTarde(start_date, end_date)
            countChannelsTarde = self.listCountEventOTTTarde(start_date, end_date)

            graphOTTNoche = self.graphOTTNoche(start_date, end_date)
            franjahorariaEventsOTTNoche = self.franjaHorarioEventOTTNoche(start_date, end_date)
            countChannelsNoche = self.listCountEventOTTNoche(start_date, end_date)


            # Retornar los datos como respuesta
            return Response(
                {
                    "totals": {
                        "franjahorariaeventottmadrugada": franjahorariaEventsOTTMadrugada,
                        "countchannelsmadrugada": countChannelsMadrugada,
                        "franjahorariaeventottmañana": franjahorariaEventsOTTMañana,
                        "countchannelsmañana": countChannelsMañana,
                        "franjahorariaeventotttarde": franjahorariaEventsOTTTarde,
                        "countchannelstarde": countChannelsTarde,
                        "franjahorariaeventottnoche": franjahorariaEventsOTTNoche,
                        "countchannelsnoche": countChannelsNoche,
                        "totaldurationott": durationOTT,
                        "franjahorariaott": franjaHorarioOOT,
                    },
                    "events": {
                        "listOTT": ottEvents,
                        "listCountEventOTT": listCountEventOTT,
                    },
                    "graphs": {
                        "graphott": graphOTT,
                        "graphottMadrugada": graphOTTMadrugada,
                        "graphottMañana": graphOTTMañana,
                        "graphottTarde": graphOTTTarde,
                        "graphottNoche": graphOTTNoche,
                    },
                },
                status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": "Error inesperado al procesar la solicitud"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TelemetriaDaysDvb(APIView):
    def dataRangeDVB(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataDVB = MergedTelemetricDVB.objects.filter(dataDate__range=[start_date, today])
            else:
                dataDVB = MergedTelemetricDVB.objects.all()
            
            durationDVB = sum(item.dataDuration if item.dataDuration is not None else 0 for item in dataDVB) / 3600
            DVB = round(durationDVB, 2)
            return {"duration": DVB, "start_date": start_date, "end_date": today}
        
        except Exception as e:
            return None

    def franjaHorarioDVB(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataDVB = MergedTelemetricDVB.objects.filter(dataDate__range=[start_date, today])
            else:
                dataDVB = MergedTelemetricDVB.objects.all()

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

            data_duration_by_franja = {franja: round(duration, 2) for franja, duration in data_duration_by_franja.items()}
            
            result = dict(data_duration_by_franja)

            return result
        except ValidationError as e:  # Captura específicamente las excepciones de validación
            print(f"Error de validación durante la serialización: {e}")
            return None
        except Exception as e:  # Captura otras excepciones
            print(f"Ocurrió un error durante la serialización: {e}")
            return None

    def listEventDVB(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataDVB = MergedTelemetricDVB.objects.filter(dataDate__range=[start_date, today])
            else:
                dataDVB = MergedTelemetricDVB.objects.all()

            # Diccionario para almacenar la suma de dataDuration para cada dataName
            data_duration_by_name = defaultdict(float)

            for item in dataDVB:
                # Suma dataDuration para cada dataName
                data_duration_by_name[item.dataName] += item.dataDuration /3600 if item.dataDuration else 0
            
            rounded_data = {data_name: round(duration, 2) for data_name, duration in data_duration_by_name.items()}

            return rounded_data

        except ValidationError as e:
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None

    def franjaHorarioEventDVB(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataDVB = MergedTelemetricDVB.objects.filter(dataDate__range=[start_date, today])
            else:
                dataDVB = MergedTelemetricDVB.objects.all()

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

        except ValidationError as e:  # Captura específicamente las excepciones de validación
            print(f"Error de validación durante la consulta a la base de datos: {e}")
            return None
        except Exception as e:  # Captura otras excepciones
            print(f"Ocurrió un error durante la consulta a la base de datos: {e}")
            return None


    def listCountEventDVB(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataOTT = MergedTelemetricDVB.objects.filter(dataDate__range=[start_date, today])
            else:
                dataOTT = MergedTelemetricDVB.objects.all()
            
            ott = {}
            for item in dataOTT:
                event = item.dataName
                ott[event] = ott.get(event, 0) + 1
            return ott
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, days=None):
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
                    "franjahorariaeventodvb":franjahorariaEventsDVB,
                    "listDVB": dvbEvents,
                    "listCountEventDVB":listCountEventDVB,
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