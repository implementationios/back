from django.http import HttpRequest
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
    try:
        logger.info("Iniciando actualización de datos OTT...")
        UpdateDataOTT().data_ott()  # Llamamos al método estático de la vista
        logger.info("Actualización de datos OTT completada con éxito.")
    except Exception as e:
        logger.error(f"Error en la actualización de datos OTT: {e}")
        raise

def update_data_dvb():
    try:
        logger.info("Iniciando actualización de datos DVB...")
        UpdateDataDVB().dataDVB()  # Llamamos al método estático de la vista
        logger.info("Actualización de datos DVB completada con éxito.")
    except Exception as e:
        logger.error(f"Error en la actualización de datos DVB: {e}")
        raise

def update_data_end_catchup():
    """
    Lógica para manejar el fin de catchup.
    """
    try:
        logger.info("Iniciando manejo de fin de catchup...")
        UpdateDataEndCatchup().dataEnd()
        logger.info("Manejo de fin de catchup completado con éxito.")
    except Exception as e:
        logger.error(f"Error en el manejo de fin de catchup: {e}")
        raise

def update_data_stop_catchup():
    """
    Lógica para manejar el fin de catchup.
    """
    try:
        logger.info("Iniciando manejo de fin de catchup...")
        UpdateDataStopCatchup().dataStop()
        logger.info("Manejo de fin de catchup completado con éxito.")
    except Exception as e:
        logger.error(f"Error en el manejo de fin de catchup: {e}")
        raise

def update_data_stop_vod():
    """
    Lógica para manejar la pausa de VOD.
    """
    try:
        logger.info("Iniciando manejo de pausa de VOD...")
        UpdateDataStopVOD().dataStop()
        logger.info("Manejo de pausa de VOD completado con éxito.")
    except Exception as e:
        logger.error(f"Error en el manejo de pausa de VOD: {e}")
        raise

def update_data_end_vod():
    """
    Lógica para manejar el fin de VOD.
    """
    try:
        logger.info("Iniciando manejo de fin de VOD...")
        UpdateDataEndVOD().dataEnd()
        logger.info("Manejo de fin de VOD completado con éxito.")
    except Exception as e:
        logger.error(f"Error en el manejo de fin de VOD: {e}")
        raise
