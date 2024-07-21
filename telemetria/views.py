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

from datetime import datetime, timedelta

from functools import wraps

import json
import gzip
import logging
import time
import orjson
import hashlib
import requests

from .models import Telemetria, MergedTelemetricOTT, MergedTelemetricDVB, MergedTelemetricStopCatchup, MergedTelemetricEndCatchup, MergedTelemetricStopVOD, MergedTelemetricEndVOD  # Importa los modelos necesarios
from .serializer import TelemetriaSerializer, MergedTelemetricOTTSerializer, MergedTelemetricDVBSerializer, MergedTelemetricCatchupSerializer, MergedTelemetricVODSerializer # Importa los serializadores necesarios

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
    # Obtener los recordIds de los datos y verificar los existentes en la base de datos
    record_ids = {item['recordId'] for item in data_batch if 'recordId' in item}
    existing_record_ids = set(Telemetria.objects.filter(
        recordId__in=record_ids
    ).values_list('recordId', flat=True))

    batch_size = 1000
    total_processed = 0
    total_invalid = 0
    with transaction.atomic():
        telemetry_objects = []
        for item in data_batch:
            if item.get('recordId') not in existing_record_ids:
                serializer = TelemetriaSerializer(data=item)
                if serializer.is_valid():
                    telemetry_object = Telemetria(**serializer.validated_data)
                    telemetry_objects.append(telemetry_object)
                    total_processed += 1
                else:
                    logger.warning(f"Invalid data: {serializer.errors}")
                    total_invalid += 1

            # Almacenar en la base de datos en lotes
            if len(telemetry_objects) >= batch_size:
                Telemetria.objects.bulk_create(telemetry_objects, ignore_conflicts=True)
                logger.info(f"Inserted batch of {len(telemetry_objects)} objects")
                telemetry_objects = []

        # Almacenar cualquier dato restante en la base de datos
        if telemetry_objects:
            Telemetria.objects.bulk_create(telemetry_objects, ignore_conflicts=True)
            logger.info(f"Inserted final batch of {len(telemetry_objects)} objects")

    logger.info(f"Total processed: {total_processed}, Total invalid: {total_invalid}")

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

@method_decorator(csrf_exempt, name='dispatch')
class TestFetchAndStoreTelemetry(View):
    def post(self, request, *args, **kwargs):
        try:
            # Credenciales proporcionadas para la prueba
            username = "yab_analitics"
            password = "Analizar321!"
            cv_token = "AhmLeBqnOJzPZzkeuXKa"
            limit = 1000

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
            store_telemetry_data(processed_data)

            return JsonResponse({
                "message": message,
                "data": processed_data
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

class MergeData(APIView):
    @timeit
    def post(self, request, *args, **kwargs):
        start_time = time.time()
        try:
            # Descompresión y decodificación de datos
            decompress_start_time = time.time()
            compressed_data = request.body
            decompressed_data = gzip.decompress(compressed_data)
            decompress_end_time = time.time()
            logger.info(f"Decompression took {decompress_end_time - decompress_start_time:.4f} seconds")

            # Conversión a objeto Python
            json_load_start_time = time.time()
            data_batch = orjson.loads(decompressed_data)
            json_load_end_time = time.time()
            logger.info(f"JSON load took {json_load_end_time - json_load_start_time:.4f} seconds")

            # Obtención de recordIds existentes
            record_ids_start_time = time.time()
            record_ids = {item['recordId'] for item in data_batch if 'recordId' in item}
            existing_record_ids = set(Telemetria.objects.filter(
                recordId__in=record_ids
            ).values_list('recordId', flat=True))
            record_ids_end_time = time.time()
            logger.info(f"Fetching existing recordIds took {record_ids_end_time - record_ids_start_time:.4f} seconds")

            # Creación e inserción de objetos Telemetria
            process_start_time = time.time()
            batch_size = 1000
            total_processed = 0
            total_invalid = 0
            with transaction.atomic():
                telemetry_objects = []
                for item in data_batch:
                    if item.get('recordId') not in existing_record_ids:
                        serializer = TelemetriaSerializer(data=item)
                        if serializer.is_valid():
                            # Crear el objeto Telemetria sin guardarlo en la base de datos
                            telemetry_object = Telemetria(**serializer.validated_data)
                            telemetry_objects.append(telemetry_object)
                            total_processed += 1
                        else:
                            logger.warning(f"Invalid data: {serializer.errors}")
                            total_invalid += 1
                    
                    if len(telemetry_objects) >= batch_size:
                        Telemetria.objects.bulk_create(telemetry_objects, ignore_conflicts=True)
                        logger.info(f"Inserted batch of {len(telemetry_objects)} objects")
                        telemetry_objects = []

                if telemetry_objects:
                    Telemetria.objects.bulk_create(telemetry_objects, ignore_conflicts=True)
                    logger.info(f"Inserted final batch of {len(telemetry_objects)} objects")

            process_end_time = time.time()
            logger.info(f"Processing and inserting data took {process_end_time - process_start_time:.4f} seconds")
            logger.info(f"Total processed: {total_processed}, Total invalid: {total_invalid}")

            end_time = time.time()
            logger.info(f"Total processing time: {end_time - start_time:.4f} seconds")

            return Response({
                "message": "Data processed successfully.",
                "total_processed": total_processed,
                "total_invalid": total_invalid
            }, status=status.HTTP_201_CREATED)

        except orjson.JSONDecodeError as e:
            logger.error(f"JSONDecodeError: {e}")
            return Response({"error": "Invalid JSON format in request body."}, status=status.HTTP_400_BAD_REQUEST)
        except KeyError as e:
            logger.error(f"KeyError: {e}")
            return Response({"error": f"Missing key in data: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self,request, *args, **kwargs):
        try:
            data = Telemetria.objects.all()
            if not data.exists():
                return Response(status=status.HTTP_204_NO_CONTENT)
            else:
                maxrecord = data.order_by("-recordId").first().recordId
                return Response({"recordId_max":maxrecord}, status=status.HTTP_200_OK)


        except json.JSONDecodeError as e:
            return Response({"error": "Invalid JSON format in request body."}, status=status.HTTP_400_BAD_REQUEST)

        except KeyError as e:
            return Response({"error": f"Missing key in data: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        except ObjectDoesNotExist as e:
            return Response({"error": "No data found."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            # Registrar el error para futuras investigaciones
            return Response({"error": "An unexpected error occurred."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

## actualización de los datos de OTT
class UpdateDataOTT(APIView):
    @staticmethod
    def data_ott():
        # Obtener datos filtrados por actionId=7 y 8 en una sola consulta
        telemetria_data = Telemetria.objects.filter(actionId__in=[7, 8]).values()

        # Crear diccionario para almacenar datos con actionId=7 y dataId como clave
        actionid7_dict = {item['dataId']: item for item in telemetria_data if item['actionId'] == 7 and item['dataId'] is not None}

        # Lista para almacenar datos fusionados
        merged_data = []

        # Fusionar datos de actionId=8 con datos de actionId=7 basándose en dataId
        for item in telemetria_data:
            if item['actionId'] == 8:
                matching_item7 = actionid7_dict.get(item['dataId'])
                if matching_item7:
                    item['dataName'] = matching_item7['dataName']
                merged_data.append(item)

        return merged_data

    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.data_ott()

            # Obtener el máximo valor de recordId en la tabla MergedTelemetricOTT
            id_maximo_registro = MergedTelemetricOTT.objects.aggregate(max_record=Max('recordId'))['max_record']

            # Manejar el caso en el que id_maximo_registro sea None
            id_maximo_registro = id_maximo_registro or 0

            # Filtrar los registros que tengan un recordId mayor que id_maximo_registro
            registros_filtrados = [registro for registro in merged_data if registro['recordId'] is not None and registro['recordId'] > id_maximo_registro]

            # Verificar si no hay registros filtrados
            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            # Verificar si la tabla MergedTelemetricOTT está vacía
            if not MergedTelemetricOTT.objects.exists():
                # Crear objetos MergedTelemetricOTT utilizando bulk_create si la tabla está vacía
                MergedTelemetricOTT.objects.bulk_create(
                    [MergedTelemetricOTT(**data) for data in merged_data],
                    ignore_conflicts=True
                )
                return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
            else:
                # Crear objetos MergedTelemetricOTT utilizando bulk_create si la tabla no está vacía
                MergedTelemetricOTT.objects.bulk_create(
                    [MergedTelemetricOTT(**data) for data in registros_filtrados],
                    ignore_conflicts=True
                )
                return Response({"message": "Creación exitosa en base llena"}, status=status.HTTP_200_OK)

        except IntegrityError:
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        # Obtiene todos los objetos de la tabla MergedTelemetricOTT en la base de datos
        data = MergedTelemetricOTT.objects.all()

        # Serializa los datos obtenidos utilizando tu propio serializador
        serializer = MergedTelemetricOTTSerializer(data, many=True)

        # Devuelve una respuesta con los datos serializados
        return Response(serializer.data, status=status.HTTP_200_OK)

## actualización de los datos de DVB
class UpdateDataDVB(APIView):
    @staticmethod
    def dataDVB():
        # Obtener datos filtrados por actionId=5 y 6 en una sola consulta
        telemetria_data = Telemetria.objects.filter(actionId__in=[5, 6]).only('dataId', 'actionId', 'dataName').iterator()

        # Crear diccionario para almacenar datos con actionId=5 y dataId como clave
        actionid5_dict = {item.dataId: item.dataName for item in telemetria_data if item.actionId == 5 and item.dataId is not None}

        # Lista para almacenar datos fusionados
        merged_data = []

        # Reiniciar el iterador para recorrer nuevamente los datos
        telemetria_data = Telemetria.objects.filter(actionId__in=[5, 6]).only('dataId', 'actionId').iterator()

        # Fusionar datos de actionId=6 con datos de actionId=5 basándose en dataId
        for item in telemetria_data:
            if item.actionId == 6:
                item.dataName = actionid5_dict.get(item.dataId)
                merged_data.append(item)

        return merged_data

    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.dataDVB()

            # Obtener el máximo valor de recordId en la tabla MergedTelemetricDVB
            id_maximo_registro = MergedTelemetricDVB.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            # Filtrar los registros que tengan un recordId mayor que id_maximo_registro
            registros_filtrados = [registro for registro in merged_data if registro.recordId is not None and registro.recordId > id_maximo_registro]

            # Verificar si no hay registros filtrados
            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                # Verificar si la tabla MergedTelemetricDVB está vacía
                if not MergedTelemetricDVB.objects.exists():
                    # Crear objetos MergedTelemetricDVB utilizando bulk_create si la tabla está vacía
                    MergedTelemetricDVB.objects.bulk_create(
                        [MergedTelemetricDVB(**data.__dict__) for data in merged_data],
                        ignore_conflicts=True
                    )
                    return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
                else:
                    # Crear objetos MergedTelemetricDVB utilizando bulk_create si la tabla no está vacía
                    MergedTelemetricDVB.objects.bulk_create(
                        [MergedTelemetricDVB(**data.__dict__) for data in registros_filtrados],
                        ignore_conflicts=True
                    )
                    return Response({"message": "Creación exitosa en base llena"}, status=status.HTTP_200_OK)

        except IntegrityError:
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        # Obtiene todos los objetos de la tabla MergedTelemetricDVB en la base de datos
        data = MergedTelemetricDVB.objects.all()
        
        # Serializa los datos obtenidos utilizando tu propio serializador
        serializer = MergedTelemetricDVBSerializer(data, many=True)
        
        # Devuelve una respuesta con los datos serializados
        return Response(serializer.data, status=status.HTTP_200_OK)
## actualización de los datos de catchup pausado
class UpdateDataStopCatchup(APIView):
    def dataStop(self):
        # Obtener datos filtrados por actionId=17
        telemetria_data_actionid16 = Telemetria.objects.filter(actionId=16).values()
        
        # Obtener datos filtrados por actionId=6
        telemetria_data_actionid17 = Telemetria.objects.filter(actionId=17).values()

        # Fusionar los datos relacionados
        merged_data = []
        for item17 in telemetria_data_actionid17:
            matching_item16 = next((item16 for item16 in telemetria_data_actionid16 if item16['dataId'] == item17['dataId']), None)
            if matching_item16:
                item17['dataName'] = matching_item16['dataName']
            merged_data.append(item17)

        return merged_data
    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.dataStop()
            # Obtener el máximo valor de recordId en la tabla MergedTelemetricStopCatchup
            id_maximo_registro = MergedTelemetricStopCatchup.objects.aggregate(max_record=Max('recordId'))['max_record']

            # Manejar el caso en el que id_maximo_registro sea None
            if id_maximo_registro is None:
                id_maximo_registro = 0

            # Filtrar los registros que tengan un recordId mayor que id_maximo_registro
            registros_filtrados = [registro for registro in merged_data if registro['recordId'] > id_maximo_registro]

            # Verificar si no hay registros filtrados
            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            # Verificar si el máximo registro en la base de datos es igual al máximo entre los registros filtrados
            if id_maximo_registro == max(registro['recordId'] for registro in registros_filtrados):
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            # Verificar si la tabla MergedTelemetricStopCatchup está vacía
            if not MergedTelemetricStopCatchup.objects.exists():
                # Crear objetos MergedTelemetricStopCatchup utilizando bulk_create si la tabla está vacía
                MergedTelemetricStopCatchup.objects.bulk_create([MergedTelemetricStopCatchup(**data) for data in merged_data])
                return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
            else:
                # Crear objetos MergedTelemetricStopCatchup utilizando bulk_create si la tabla no está vacía
                MergedTelemetricStopCatchup.objects.bulk_create([MergedTelemetricStopCatchup(**data) for data in registros_filtrados])
                return Response({"message": "Creación exitosa en base llena"}, status=status.HTTP_200_OK)

        except IntegrityError:
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        # Obtiene todos los objetos de la tabla MergedTelemetricStopCatchup en la base de datos
        data = MergedTelemetricStopCatchup.objects.all()
        
        # Serializa los datos obtenidos utilizando tu propio serializador
        serializer = MergedTelemetricCatchupSerializer(data, many=True)
        
        # Devuelve una respuesta con los datos serializados
        return Response(serializer.data, status=status.HTTP_200_OK)

## actualización de los datos de catchup terminado
class UpdateDataEndCatchup(APIView):
    @staticmethod
    def dataEnd():
        # Obtener datos filtrados por actionId=16 y 18 en una sola consulta
        telemetria_data = Telemetria.objects.filter(actionId__in=[16, 18]).only('dataId', 'actionId', 'dataName').iterator()

        # Crear diccionario para almacenar datos con actionId=16 y dataId como clave
        actionid16_dict = {item.dataId: item.dataName for item in telemetria_data if item.actionId == 16 and item.dataId is not None}

        # Lista para almacenar datos fusionados
        merged_data = []

        # Reiniciar el iterador para recorrer nuevamente los datos
        telemetria_data = Telemetria.objects.filter(actionId__in=[16, 18]).only('dataId', 'actionId').iterator()

        # Fusionar datos de actionId=18 con datos de actionId=16 basándose en dataId
        for item in telemetria_data:
            if item.actionId == 18:
                item.dataName = actionid16_dict.get(item.dataId)
                merged_data.append(item)

        return merged_data

    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.dataEnd()

            # Obtener el máximo valor de recordId en la tabla MergedTelemetricEndCatchup
            id_maximo_registro = MergedTelemetricEndCatchup.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            # Filtrar los registros que tengan un recordId mayor que id_maximo_registro
            registros_filtrados = [registro for registro in merged_data if registro.recordId is not None and registro.recordId > id_maximo_registro]

            # Verificar si no hay registros filtrados
            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                # Verificar si la tabla MergedTelemetricEndCatchup está vacía
                if not MergedTelemetricEndCatchup.objects.exists():
                    # Crear objetos MergedTelemetricEndCatchup utilizando bulk_create si la tabla está vacía
                    MergedTelemetricEndCatchup.objects.bulk_create(
                        [MergedTelemetricEndCatchup(**data.__dict__) for data in merged_data],
                        ignore_conflicts=True
                    )
                    return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
                else:
                    # Crear objetos MergedTelemetricEndCatchup utilizando bulk_create si la tabla no está vacía
                    MergedTelemetricEndCatchup.objects.bulk_create(
                        [MergedTelemetricEndCatchup(**data.__dict__) for data in registros_filtrados],
                        ignore_conflicts=True
                    )
                    return Response({"message": "Creación exitosa en base llena"}, status=status.HTTP_200_OK)

        except IntegrityError:
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        # Obtiene todos los objetos de la tabla MergedTelemetricEndCatchup en la base de datos
        data = MergedTelemetricEndCatchup.objects.all()
        
        # Serializa los datos obtenidos utilizando tu propio serializador
        serializer = MergedTelemetricCatchupSerializer(data, many=True)
        
        # Devuelve una respuesta con los datos serializados
        return Response(serializer.data, status=status.HTTP_200_OK)

## actualización de los datos de VOD pausados
class UpdateDataStopVOD(APIView):
    @staticmethod
    def dataStop():
        # Obtener datos filtrados por actionId=13 y 14 en una sola consulta
        telemetria_data = Telemetria.objects.filter(actionId__in=[13, 14]).only('dataId', 'actionId', 'dataName').iterator()

        # Crear diccionario para almacenar datos con actionId=13 y dataId como clave
        actionid13_dict = {item.dataId: item.dataName for item in telemetria_data if item.actionId == 13 and item.dataId is not None}

        # Lista para almacenar datos fusionados
        merged_data = []

        # Reiniciar el iterador para recorrer nuevamente los datos
        telemetria_data = Telemetria.objects.filter(actionId__in=[13, 14]).only('dataId', 'actionId').iterator()

        # Fusionar datos de actionId=14 con datos de actionId=13 basándose en dataId
        for item in telemetria_data:
            if item.actionId == 14:
                item.dataName = actionid13_dict.get(item.dataId)
                merged_data.append(item)

        return merged_data

    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.dataStop()

            # Obtener el máximo valor de recordId en la tabla MergedTelemetricStopVOD
            id_maximo_registro = MergedTelemetricStopVOD.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            # Filtrar los registros que tengan un recordId mayor que id_maximo_registro
            registros_filtrados = [registro for registro in merged_data if registro.recordId is not None and registro.recordId > id_maximo_registro]

            # Verificar si no hay registros filtrados
            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                # Verificar si la tabla MergedTelemetricStopVOD está vacía
                if not MergedTelemetricStopVOD.objects.exists():
                    # Crear objetos MergedTelemetricStopVOD utilizando bulk_create si la tabla está vacía
                    MergedTelemetricStopVOD.objects.bulk_create(
                        [MergedTelemetricStopVOD(**data.__dict__) for data in merged_data],
                        ignore_conflicts=True
                    )
                    return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
                else:
                    # Crear objetos MergedTelemetricStopVOD utilizando bulk_create si la tabla no está vacía
                    MergedTelemetricStopVOD.objects.bulk_create(
                        [MergedTelemetricStopVOD(**data.__dict__) for data in registros_filtrados],
                        ignore_conflicts=True
                    )
                    return Response({"message": "Creación exitosa en base llena"}, status=status.HTTP_200_OK)

        except IntegrityError:
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        # Obtiene todos los objetos de la tabla MergedTelemetricStopVOD en la base de datos
        data = MergedTelemetricStopVOD.objects.all()
        
        # Serializa los datos obtenidos utilizando tu propio serializador
        serializer = MergedTelemetricVODSerializer(data, many=True)
        
        # Devuelve una respuesta con los datos serializados
        return Response(serializer.data, status=status.HTTP_200_OK)

# ## actualización de los datos de VOD terminado
class UpdateDataEndVOD(APIView):
    @staticmethod
    def dataEnd():
        # Obtener datos filtrados por actionId=16 y 18 en una sola consulta
        telemetria_data = Telemetria.objects.filter(actionId__in=[16, 18]).only('dataId', 'actionId', 'dataName').iterator()

        # Crear diccionario para almacenar datos con actionId=16 y dataId como clave
        actionid16_dict = {item.dataId: item.dataName for item in telemetria_data if item.actionId == 16 and item.dataId is not None}

        # Lista para almacenar datos fusionados
        merged_data = []

        # Reiniciar el iterador para recorrer nuevamente los datos
        telemetria_data = Telemetria.objects.filter(actionId__in=[16, 18]).only('dataId', 'actionId').iterator()

        # Fusionar datos de actionId=18 con datos de actionId=16 basándose en dataId
        for item in telemetria_data:
            if item.actionId == 18:
                item.dataName = actionid16_dict.get(item.dataId)
                merged_data.append(item)

        return merged_data

    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.dataEnd()

            # Obtener el máximo valor de recordId en la tabla MergedTelemetricEndVOD
            id_maximo_registro = MergedTelemetricEndVOD.objects.aggregate(max_record=Max('recordId'))['max_record'] or 0

            # Filtrar los registros que tengan un recordId mayor que id_maximo_registro
            registros_filtrados = [registro for registro in merged_data if registro.recordId is not None and registro.recordId > id_maximo_registro]

            # Verificar si no hay registros filtrados
            if not registros_filtrados:
                return Response({"message": "No hay nuevos registros para crear"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                # Verificar si la tabla MergedTelemetricEndVOD está vacía
                if not MergedTelemetricEndVOD.objects.exists():
                    # Crear objetos MergedTelemetricEndVOD utilizando bulk_create si la tabla está vacía
                    MergedTelemetricEndVOD.objects.bulk_create(
                        [MergedTelemetricEndVOD(**data.__dict__) for data in merged_data],
                        ignore_conflicts=True
                    )
                    return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
                else:
                    # Crear objetos MergedTelemetricEndVOD utilizando bulk_create si la tabla no está vacía
                    MergedTelemetricEndVOD.objects.bulk_create(
                        [MergedTelemetricEndVOD(**data.__dict__) for data in registros_filtrados],
                        ignore_conflicts=True
                    )
                    return Response({"message": "Creación exitosa en base llena"}, status=status.HTTP_200_OK)

        except IntegrityError:
            return Response({"error": "Error de integridad al guardar datos"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, *args, **kwargs):
        # Obtiene todos los objetos de la tabla MergedTelemetricEndVOD en la base de datos
        data = MergedTelemetricEndVOD.objects.all()
        
        # Serializa los datos obtenidos utilizando tu propio serializador
        serializer = MergedTelemetricVODSerializer(data, many=True)
        
        # Devuelve una respuesta con los datos serializados
        return Response(serializer.data, status=status.HTTP_200_OK)

class TelemetriaHome(APIView):
    def dataRangeOTT(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataOTT = MergedTelemetricOTT.objects.filter(dataDate__range=[start_date, today])
            else:
                dataOTT = MergedTelemetricOTT.objects.all()
            
            durationOTT = sum(item.dataDuration if item.dataDuration is not None else 0 for item in dataOTT) / 3600
            OTT = round(durationOTT, 2)
            return {"duration": OTT, "start_date": start_date, "end_date": today}
        
        except ValidationError as e:  # Captura específicamente las excepciones de validación
            print(f"Error de validación durante la serialización: {e}")
            return None
        except Exception as e:  # Captura otras excepciones
            print(f"Ocurrió un error durante la serialización: {e}")
            return None

    def franjaHorarioOTT(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataOTT = MergedTelemetricOTT.objects.filter(dataDate__range=[start_date, today])
            else:
                dataOTT = MergedTelemetricOTT.objects.all()

            data_duration_by_franja = defaultdict(float)
            franjas = {
                "Madrugada": (0, 5),
                "Mañana": (5, 12),
                "Tarde": (12, 18),
                "Noche": (18, 24)
            }

            for item in dataOTT:
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

    def listEventOTT(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataOTT = MergedTelemetricOTT.objects.filter(dataDate__range=[start_date, today])
            else:
                dataOTT = MergedTelemetricOTT.objects.all()

            # Diccionario para almacenar la suma de dataDuration para cada dataName
            data_duration_by_name = defaultdict(float)

            for item in dataOTT:
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
    
    def listCountEventOTT(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataOTT = MergedTelemetricOTT.objects.filter(dataDate__range=[start_date, today])
            else:
                dataOTT = MergedTelemetricOTT.objects.all()
            
            ott = {}
            for item in dataOTT:
                event = item.dataName
                ott[event] = ott.get(event, 0) + 1
            return ott
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def franjaHorarioEventOTT(self, days):
        try:
            if days > 0:
                today = datetime.now().date()
                start_date = today - timedelta(days=days)
                dataOTT = MergedTelemetricOTT.objects.filter(dataDate__range=[start_date, today])
            else:
                dataOTT = MergedTelemetricOTT.objects.all()

            data_duration_by_franja = defaultdict(lambda: defaultdict(float))
            franjas = {
                "Madrugada": (0, 5),
                "Mañana": (5, 12),
                "Tarde": (12, 18),
                "Noche": (18, 24)
            }

            for item in dataOTT:
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
            durationOTT = self.dataRangeOTT(days)
            franjaHorarioOOT = self.franjaHorarioOTT(days)
            ottEvents = self.listEventOTT(days)
            franjahorariaEventsOTT = self.franjaHorarioEventOTT(days)
            listCountEventOTT = self.listCountEventOTT(days)
            durationDVB = self.dataRangeDVB(days)
            franjaHorariaDVB = self.franjaHorarioDVB(days)
            franjahorariaEventsDVB = self.franjaHorarioEventDVB(days)
            dvbEvents = self.listEventDVB(days)
            listCountEventDVB = self.listCountEventDVB(days)
            vodCount = self.countVOD(days)
            vodEvents = self.listEventVOD(days)
            catchupCount = self.countCatchup(days)
            catchupEvents = self.listEventCatchup(days)
            return Response(
                {
                    "totaldurationott": durationOTT,
                    "franjahorariaott": franjaHorarioOOT,
                    "listOTT": ottEvents,
                    "franjahorariaeventott":franjahorariaEventsOTT,
                    "listCountEventOTT":listCountEventOTT,
                    "totaldurationdvb": durationDVB,
                    "franjahorariadvb": franjaHorariaDVB,
                    "franjahorariaeventodvb":franjahorariaEventsDVB,
                    "listDVB": dvbEvents,
                    "listCountEventDVB":listCountEventDVB,
                    "vodCount":vodCount,
                    "vodeventos": vodEvents,
                    "catchupCount" : catchupCount,
                    "catchupeventos": catchupEvents,
                },
                status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
