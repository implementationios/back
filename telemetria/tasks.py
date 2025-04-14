from .services import (
    fetch_and_store_telemetry,
    update_data_ott,
    update_data_dvb,
    update_data_stop_catchup,
    update_data_end_catchup,
    update_data_stop_vod,
    update_data_end_vod,
)
import logging

logger = logging.getLogger(__name__)

def test_fetch_store_telemetry():
    """
    Tarea para obtener y almacenar datos de telemetría.
    """
    try:
        fetch_and_store_telemetry()
    except Exception as e:
        logger.error(f"Error en test_fetch_store_telemetry: {e}")
        raise

def update_data_ott_task():
    """
    Tarea para actualizar datos OTT.
    """
    try:
        update_data_ott()
    except Exception as e:
        logger.error(f"Error en update_data_ott_task: {e}")
        raise

def update_data_dvb_task():
    """
    Tarea para actualizar datos DVB.
    """
    try:
        update_data_dvb()
    except Exception as e:
        logger.error(f"Error en update_data_dvb_task: {e}")
        raise

def update_data_stop_catchup_task():
    """
    Tarea para manejar el pausa de catchup.
    """
    try:
        update_data_stop_catchup()
    except Exception as e:
        logger.error(f"Error en update_data_end_catchup_task: {e}")
        raise

def update_data_end_catchup_task():
    """
    Tarea para manejar el fin de catchup.
    """
    try:
        update_data_end_catchup()
    except Exception as e:
        logger.error(f"Error en update_data_end_catchup_task: {e}")
        raise

def update_data_stop_vod_task():
    """
    Tarea para manejar la pausa de VOD.
    """
    try:
        update_data_stop_vod()
    except Exception as e:
        logger.error(f"Error en update_data_stop_vod_task: {e}")
        raise

def update_data_end_vod_task():
    """
    Tarea para manejar el fin de VOD.
    """
    try:
        update_data_end_vod()
    except Exception as e:
        logger.error(f"Error en update_data_end_vod_task: {e}")
        raise
