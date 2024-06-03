# Importa las bibliotecas y módulos necesarios
from collections import defaultdict

from django.views.decorators.csrf import csrf_exempt  # Desactiva la protección CSRF
from django.views.decorators.http import require_POST  # Requiere que la solicitud sea de tipo POST

from django.utils.decorators import method_decorator
from django.utils import timezone

from django.db import IntegrityError

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

import json
import gzip

from .models import Telemetria, MergedTelemetricOTT, MergedTelemetricDVB, MergedTelemetricStopCatchup, MergedTelemetricEndCatchup, MergedTelemetricStopVOD, MergedTelemetricEndVOD  # Importa los modelos necesarios
from .serializer import TelemetriaSerializer, MergedTelemetricOTTSerializer, MergedTelemetricDVBSerializer, MergedTelemetricCatchupSerializer, MergedTelemetricVODSerializer # Importa los serializadores necesarios

# Decora la vista para deshabilitar la protección CSRF y permitir solicitudes POST sin autenticación
@csrf_exempt
@require_POST
def DataTelemetria(request):
    try:
        # Descomprimir los datos Gzip
        compressed_data = request.body
        decompressed_data = gzip.decompress(compressed_data).decode('utf-8')

        # Parsear los datos descomprimidos del cuerpo de la solicitud como JSON
        data_batch = json.loads(decompressed_data)

        # Lista para almacenar respuestas individuales para cada registro en el lote
        responses = []
        telemetria_instances = []

        # Crear instancias de Telemetria
        for data in data_batch:
            existing_record = Telemetria.objects.filter(recordId=data.get('recordId')).first()
            if existing_record:
                return JsonResponse({'status': 'success', 'message': 'Duplicate record'})
            else:
                telemetria_instances.append(Telemetria(
                    actionId=data.get('actionId'),
                    actionKey=data.get('actionKey'),
                    anonymized=data.get('anonymized'),
                    dataDuration=data.get('dataDuration'),
                    dataId=data.get('dataId'),
                    dataName=data.get('dataName'),
                    dataNetId=data.get('dataNetId'),
                    dataPrice=data.get('dataPrice'),
                    dataSeviceId=data.get('dataSeviceId'),
                    dataTsId=data.get('dataTsId'),
                    date=data.get('date'),
                    deviceId=data.get('deviceId'),
                    ip=data.get('ip'),
                    ipId=data.get('ipId'),
                    manual=data.get('manual'),
                    profileId=data.get('profileId'),
                    reaonId=data.get('reaonId'),
                    reasonKey=data.get('reasonKey'),
                    recordId=data.get('recordId'),
                    smartcardId=data.get('smartcardId'),
                    subscriberCode=data.get('subscriberCode'),
                    timestamp=data.get('timestamp'),
                    dataDate=data.get('dataDate'),
                    timeDate=data.get('timeDate'),
                    whoisCountry=data.get('whoisCountry'),
                    whoisIsp=data.get('whoisIsp')
                ))

        # Guardar instancias de Telemetria en la base de datos
        Telemetria.objects.bulk_create(telemetria_instances)

        # Crear respuestas exitosas
        responses.extend([{'status': 'success'} for _ in telemetria_instances])
        
        # Devolver las respuestas para cada registro en el lote
        return JsonResponse(responses, safe=False)
    except Exception as e:
        # En caso de error, devuelve una respuesta de error con un mensaje
        return JsonResponse({'status': 'error', 'message': str(e)})

## funcion para poder almacenar los registros en la base de datos
class MergeData(APIView):
    def post(self, request, *args, **kwargs):
        try:
            # Obtener los datos comprimidos del cuerpo de la solicitud
            compressed_data = request.body
            
            # Descomprimir los datos y decodificarlos como UTF-8
            decompressed_data = gzip.decompress(compressed_data).decode('utf-8')
            
            # Convertir los datos descomprimidos en un objeto Python
            data_batch = json.loads(decompressed_data)
            
            # Iterar sobre cada conjunto de datos fusionados
            for merged in data_batch:
                # Obtener el 'recordId' del conjunto de datos actual
                record_id = merged.get('recordId')
                
                # Verificar si ya existe un objeto con el mismo 'recordId'
                if record_id:
                    if Telemetria.objects.filter(recordId=record_id).exists():
                        # Devolver un error si ya existe un objeto con el mismo 'recordId'
                        return Response({"error": f"Registro con recordId '{record_id}' ya existe en la base de datos."}, status=status.HTTP_409_CONFLICT)
                    else:
                        # Crear un nuevo objeto Telemetria con los datos fusionados
                        Telemetria.objects.create(**merged)
            
            # Devolver un mensaje de éxito si se procesaron todos los datos correctamente
            return Response({"message": "Data processed successfully."}, status=status.HTTP_200_OK)
        
        # Manejar excepciones si hay errores al decodificar los datos JSON
        except json.JSONDecodeError as e:
            return Response({"error": "Invalid JSON format in request body."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Manejar excepciones si falta una clave en los datos fusionados
        except KeyError as e:
            return Response({"error": f"Missing key in data: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Manejar cualquier otra excepción no manejada
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get(self, request, *args, **kwargs):
        try:
            data = Telemetria.objects.all()
            if not data.exists():
                return Response(status=status.HTTP_202_ACCEPTED)
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
        # Obtener datos filtrados por actionId=7
        telemetria_data_actionid7 = Telemetria.objects.filter(actionId=7).values()

        # Obtener datos filtrados por actionId=8
        telemetria_data_actionid8 = Telemetria.objects.filter(actionId=8).values()

        # Fusionar los datos relacionados
        merged_data = []
        for item8 in telemetria_data_actionid8:
            # Buscar el elemento correspondiente en telemetria_data_actionid7 que coincida con dataId
            matching_item7 = next((item7 for item7 in telemetria_data_actionid7 if item7['dataId'] == item8['dataId']), None)
            if matching_item7:
                # Agregar el nombre de los datos de telemetria_data_actionid7 al elemento de telemetria_data_actionid8
                item8['dataName'] = matching_item7['dataName']
            # Agregar el elemento fusionado a la lista merged_data
            merged_data.append(item8)

        return merged_data

    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.data_ott()
            # Obtener el máximo valor de recordId en la tabla MergedTelemetricOTT
            id_maximo_registro = MergedTelemetricOTT.objects.aggregate(max_record=Max('recordId'))['max_record']

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

            # Verificar si la tabla MergedTelemetricOTT está vacía
            if not MergedTelemetricOTT.objects.exists():
                # Crear objetos MergedTelemetricOTT utilizando bulk_create si la tabla está vacía
                MergedTelemetricOTT.objects.bulk_create([MergedTelemetricOTT(**data) for data in merged_data])
                return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
            else:
                # Crear objetos MergedTelemetricOTT utilizando bulk_create si la tabla no está vacía
                MergedTelemetricOTT.objects.bulk_create([MergedTelemetricOTT(**data) for data in registros_filtrados])
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
    def dataDVB(self):
        # Obtener datos filtrados por actionId=5
        telemetria_data_actionid5 = Telemetria.objects.filter(actionId=5).values()

        # Obtener datos filtrados por actionId=6
        telemetria_data_actionid6 = Telemetria.objects.filter(actionId=6).values()

        # Fusionar los datos relacionados
        merged_data = []
        for item6 in telemetria_data_actionid6:
            # Buscar el elemento correspondiente en telemetria_data_actionid5 que coincida con dataId
            matching_item5 = next((item5 for item5 in telemetria_data_actionid5 if item5['dataId'] == item6['dataId']), None)
            if matching_item5:
                # Agregar el nombre de los datos de telemetria_data_actionid5 al elemento de telemetria_data_actionid6
                item6['dataName'] = matching_item5['dataName']
            # Agregar el elemento fusionado a la lista merged_data
            merged_data.append(item6)

        return merged_data

    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.dataDVB()
            # Obtener el máximo valor de recordId en la tabla MergedTelemetricDVB
            id_maximo_registro = MergedTelemetricDVB.objects.aggregate(max_record=Max('recordId'))['max_record']

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

            # Verificar si la tabla MergedTelemetricDVB está vacía
            if not MergedTelemetricDVB.objects.exists():
                # Crear objetos MergedTelemetricDVB utilizando bulk_create si la tabla está vacía
                MergedTelemetricDVB.objects.bulk_create([MergedTelemetricDVB(**data) for data in merged_data])
                return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
            else:
                # Crear objetos MergedTelemetricDVB utilizando bulk_create si la tabla no está vacía
                MergedTelemetricDVB.objects.bulk_create([MergedTelemetricDVB(**data) for data in registros_filtrados])
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
    def dataEnd(self):
        # Obtener datos filtrados por actionId=17
        telemetria_data_actionid16 = Telemetria.objects.filter(actionId=16).values()
        
        # Obtener datos filtrados por actionId=6
        telemetria_data_actionid18 = Telemetria.objects.filter(actionId=18).values()

        # Fusionar los datos relacionados
        merged_data = []
        for item18 in telemetria_data_actionid18:
            matching_item16 = next((item16 for item16 in telemetria_data_actionid16 if item16['dataId'] == item18['dataId']), None)
            if matching_item16:
                item18['dataName'] = matching_item16['dataName']
            merged_data.append(item18)

        return merged_data
    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.dataEnd()
            # Obtener el máximo valor de recordId en la tabla MergedTelemetricEndCatchup
            id_maximo_registro = MergedTelemetricEndCatchup.objects.aggregate(max_record=Max('recordId'))['max_record']

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

            # Verificar si la tabla MergedTelemetricEndCatchup está vacía
            if not MergedTelemetricEndCatchup.objects.exists():
                # Crear objetos MergedTelemetricEndCatchup utilizando bulk_create si la tabla está vacía
                MergedTelemetricEndCatchup.objects.bulk_create([MergedTelemetricEndCatchup(**data) for data in merged_data])
                return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
            else:
                # Crear objetos MergedTelemetricEndCatchup utilizando bulk_create si la tabla no está vacía
                MergedTelemetricEndCatchup.objects.bulk_create([MergedTelemetricEndCatchup(**data) for data in registros_filtrados])
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
    def dataStop(self):
        # Obtener datos filtrados por actionId=17
        telemetria_data_actionid13 = Telemetria.objects.filter(actionId=13).values()
        
        # Obtener datos filtrados por actionId=6
        telemetria_data_actionid14 = Telemetria.objects.filter(actionId=14).values()

        # Fusionar los datos relacionados
        merged_data = []
        for item14 in telemetria_data_actionid14:
            matching_item13 = next((item13 for item13 in telemetria_data_actionid13 if item13['dataId'] == item14['dataId']), None)
            if matching_item13:
                item14['dataName'] = matching_item13['dataName']
            merged_data.append(item14)

        return merged_data
    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.dataStop()
            # Obtener el máximo valor de recordId en la tabla MergedTelemetricStopVOD
            id_maximo_registro = MergedTelemetricStopVOD.objects.aggregate(max_record=Max('recordId'))['max_record']

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

            # Verificar si la tabla MergedTelemetricStopVOD está vacía
            if not MergedTelemetricStopVOD.objects.exists():
                # Crear objetos MergedTelemetricStopVOD utilizando bulk_create si la tabla está vacía
                MergedTelemetricStopVOD.objects.bulk_create([MergedTelemetricStopVOD(**data) for data in merged_data])
                return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
            else:
                # Crear objetos MergedTelemetricStopVOD utilizando bulk_create si la tabla no está vacía
                MergedTelemetricStopVOD.objects.bulk_create([MergedTelemetricStopVOD(**data) for data in registros_filtrados])
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
    def dataEnd(self):
        # Obtener datos filtrados por actionId=17
        telemetria_data_actionid16 = Telemetria.objects.filter(actionId=16).values()
        
        # Obtener datos filtrados por actionId=6
        telemetria_data_actionid18 = Telemetria.objects.filter(actionId=18).values()

        # Fusionar los datos relacionados
        merged_data = []
        for item18 in telemetria_data_actionid18:
            matching_item16 = next((item16 for item16 in telemetria_data_actionid16 if item16['dataId'] == item18['dataId']), None)
            if matching_item16:
                item18['dataName'] = matching_item16['dataName']
            merged_data.append(item18)

        return merged_data
    def post(self, request):
        try:
            # Obtener datos fusionados
            merged_data = self.dataEnd()
            # Obtener el máximo valor de recordId en la tabla MergedTelemetricEndVOD
            id_maximo_registro = MergedTelemetricEndVOD.objects.aggregate(max_record=Max('recordId'))['max_record']

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

            # Verificar si la tabla MergedTelemetricEndVOD está vacía
            if not MergedTelemetricEndVOD.objects.exists():
                # Crear objetos MergedTelemetricEndVOD utilizando bulk_create si la tabla está vacía
                MergedTelemetricEndVOD.objects.bulk_create([MergedTelemetricEndVOD(**data) for data in merged_data])
                return Response({"message": "Creación exitosa en base vacía"}, status=status.HTTP_200_OK)
            else:
                # Crear objetos MergedTelemetricEndVOD utilizando bulk_create si la tabla no está vacía
                MergedTelemetricEndVOD.objects.bulk_create([MergedTelemetricEndVOD(**data) for data in registros_filtrados])
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
            durationDVB = self.dataRangeDVB(days)
            franjaHorariaDVB = self.franjaHorarioDVB(days)
            franjahorariaEventsDVB = self.franjaHorarioEventDVB(days)
            dvbEvents = self.listEventDVB(days)
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
                    "totaldurationdvb": durationDVB,
                    "franjahorariadvb": franjaHorariaDVB,
                    "listDVB": dvbEvents,
                    "franjahorariaeventodvb":franjahorariaEventsDVB,
                    "vodCount":vodCount,
                    "vodeventos": vodEvents,
                    "catchupCount" : catchupCount,
                    "catchupeventos": catchupEvents,
                },
                status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
