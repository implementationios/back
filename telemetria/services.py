from django.http import HttpRequest
from rest_framework.test import APIRequestFactory
from django.urls import reverse
from .views import UpdateDataOTT, UpdateDataDVB, UpdateDataStopCatchup, UpdateDataEndCatchup, UpdateDataStopVOD, UpdateDataEndVOD
import logging

logger = logging.getLogger(__name__)

def fetch_and_store_telemetry():
    try:
        logger.info("Iniciando obtención y almacenamiento de datos de telemetría...")
        from .views import TestFetchAndStoreTelemetry  # Asumiendo que está en views.py
        view = TestFetchAndStoreTelemetry()
        request = HttpRequest()
        request.method = 'POST'
        view.post(request)
        logger.info("Datos de telemetría obtenidos y almacenados con éxito.")
    except Exception as e:
        logger.error(f"Error al obtener y almacenar datos de telemetría: {e}")
        raise

def update_data_ott():
    """
    Función para iniciar la actualización de los datos de la tabla MergedTelemetricOTT.
    Utiliza la vista UpdateDataOTT mediante una simulación de petición POST interna.
    """
    try:
        logger.info("Iniciando actualización de datos OTT...")
        # Crea una fábrica para simular peticiones HTTP.
        factory = APIRequestFactory()
        # Genera la URL para la vista UpdateDataOTT utilizando el nombre definido en urls.py.
        request = factory.post(reverse('updatedataott'))
        # Instancia la vista UpdateDataOTT.
        view = UpdateDataOTT().as_view()
        # Llama a la vista con la petición simulada para ejecutar su lógica (método post).
        response = view(request)
        # Verifica si la respuesta de la vista indica éxito (códigos de estado 2xx).
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"Actualización de datos OTT completada con éxito: {response.data}")
        else:
            logger.error(f"Error al actualizar datos OTT. Status code: {response.status_code}, Detalles: {response.data}")
    except Exception as e:
        logger.error(f"Error en la actualización de datos OTT: {e}")
        raise

def update_data_dvb():
    """
    Función para iniciar la actualización de los datos de la tabla MergedTelemetricDVB.
    Utiliza la vista UpdateDataDVB mediante una simulación de petición POST interna.
    """
    try:
        logger.info("Iniciando actualización de datos DVB...")
        # Crea una fábrica para simular peticiones HTTP.
        factory = APIRequestFactory()
        # Genera la URL para la vista UpdateDataDVB utilizando el nombre definido en urls.py.
        request = factory.post(reverse('updatedatadvb'))
        # Instancia la vista UpdateDataDVB.
        view = UpdateDataDVB().as_view()
        # Llama a la vista con la petición simulada para ejecutar su lógica (método post).
        response = view(request)
        # Verifica si la respuesta de la vista indica éxito (códigos de estado 2xx).
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"Actualización de datos DVB completada con éxito: {response.data}")
        else:
            logger.error(f"Error al actualizar datos DVB. Status code: {response.status_code}, Detalles: {response.data}")
    except Exception as e:
        logger.error(f"Error en la actualización de datos DVB: {e}")
        raise

def update_data_stop_catchup():
    """
    Función para iniciar la actualización de los datos de la tabla MergedTelemetricStopCatchup.
    Utiliza la vista UpdateDataStopCatchup mediante una simulación de petición POST interna.
    """
    try:
        logger.info("Iniciando actualización de datos Stop Catchup...")
        # Crea una fábrica para simular peticiones HTTP.
        factory = APIRequestFactory()
        # Genera la URL para la vista UpdateDataStopCatchup utilizando el nombre definido en urls.py.
        request = factory.post(reverse('updatedatastopcatchup'))
        # Instancia la vista UpdateDataStopCatchup.
        view = UpdateDataStopCatchup().as_view()
        # Llama a la vista con la petición simulada para ejecutar su lógica (método post).
        response = view(request)
        # Verifica si la respuesta de la vista indica éxito (códigos de estado 2xx).
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"Actualización de datos Stop Catchup completada con éxito: {response.data}")
        else:
            logger.error(f"Error al actualizar datos Stop Catchup. Status code: {response.status_code}, Detalles: {response.data}")
    except Exception as e:
        logger.error(f"Error en la actualización de datos Stop Catchup: {e}")
        raise

def update_data_end_catchup():
    """
    Función para iniciar la actualización de los datos de la tabla MergedTelemetricEndCatchup.
    Utiliza la vista UpdateDataEndCatchup mediante una simulación de petición POST interna.
    """
    try:
        logger.info("Iniciando actualización de datos End Catchup...")
        # Crea una fábrica para simular peticiones HTTP.
        factory = APIRequestFactory()
        # Genera la URL para la vista UpdateDataEndCatchup utilizando el nombre definido en urls.py.
        request = factory.post(reverse('updatedataendcatchup'))
        # Instancia la vista UpdateDataEndCatchup.
        view = UpdateDataEndCatchup().as_view()
        # Llama a la vista con la petición simulada para ejecutar su lógica (método post).
        response = view(request)
        # Verifica si la respuesta de la vista indica éxito (códigos de estado 2xx).
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"Actualización de datos End Catchup completada con éxito: {response.data}")
        else:
            logger.error(f"Error al actualizar datos End Catchup. Status code: {response.status_code}, Detalles: {response.data}")
    except Exception as e:
        logger.error(f"Error en la actualización de datos End Catchup: {e}")
        raise

def update_data_stop_vod():
    """
    Función para iniciar la actualización de los datos de la tabla MergedTelemetricStopVOD.
    Utiliza la vista UpdateDataStopVOD mediante una simulación de petición POST interna.
    """
    try:
        logger.info("Iniciando actualización de datos Stop VOD...")
        # Crea una fábrica para simular peticiones HTTP.
        factory = APIRequestFactory()
        # Genera la URL para la vista UpdateDataStopVOD utilizando el nombre definido en urls.py.
        request = factory.post(reverse('updatedatastopvod'))
        # Instancia la vista UpdateDataStopVOD.
        view = UpdateDataStopVOD().as_view()
        # Llama a la vista con la petición simulada para ejecutar su lógica (método post).
        response = view(request)
        # Verifica si la respuesta de la vista indica éxito (códigos de estado 2xx).
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"Actualización de datos Stop VOD completada con éxito: {response.data}")
        else:
            logger.error(f"Error al actualizar datos Stop VOD. Status code: {response.status_code}, Detalles: {response.data}")
    except Exception as e:
        logger.error(f"Error en la actualización de datos Stop VOD: {e}")
        raise

def update_data_end_vod():
    """
    Función para iniciar la actualización de los datos de la tabla MergedTelemetricEndVOD.
    Utiliza la vista UpdateDataEndVOD mediante una simulación de petición POST interna.
    """
    try:
        logger.info("Iniciando actualización de datos End VOD...")
        # Crea una fábrica para simular peticiones HTTP.
        factory = APIRequestFactory()
        # Genera la URL para la vista UpdateDataEndVOD utilizando el nombre definido en urls.py.
        request = factory.post(reverse('updatedataendvod'))
        # Instancia la vista UpdateDataEndVOD.
        view = UpdateDataEndVOD().as_view()
        # Llama a la vista con la petición simulada para ejecutar su lógica (método post).
        response = view(request)
        # Verifica si la respuesta de la vista indica éxito (códigos de estado 2xx).
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"Actualización de datos End VOD completada con éxito: {response.data}")
        else:
            logger.error(f"Error al actualizar datos End VOD. Status code: {response.status_code}, Detalles: {response.data}")
    except Exception as e:
        logger.error(f"Error en la actualización de datos End VOD: {e}")
        raise