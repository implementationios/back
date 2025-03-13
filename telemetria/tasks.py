# tasks.py
from celery import shared_task
import logging
from .services import (
    fetch_and_store_telemetry,
    update_data_ott,
    update_data_dvb,
    update_data_stop_catchup,
    update_data_end_catchup,
    update_data_stop_vod,
    update_data_end_vod,
)

logger = logging.getLogger(__name__)

@shared_task
def test_fetch_store_telemetry():
    try:
        fetch_and_store_telemetry()
    except Exception as e:
        logger.error(f"Error en test_fetch_store_telemetry: {e}")
        raise

@shared_task
def update_data_ott_task():
    try:
        update_data_ott()
    except Exception as e:
        logger.error(f"Error en update_data_ott_task: {e}")
        raise

@shared_task
def update_data_dvb_task():
    try:
        update_data_dvb()
    except Exception as e:
        logger.error(f"Error en update_data_dvb_task: {e}")
        raise

@shared_task
def update_data_stop_catchup_task():
    try:
        update_data_stop_catchup()
    except Exception as e:
        logger.error(f"Error en update_data_stop_catchup_task: {e}")
        raise

@shared_task
def update_data_end_catchup_task():
    try:
        update_data_end_catchup()
    except Exception as e:
        logger.error(f"Error en update_data_end_catchup_task: {e}")
        raise

@shared_task
def update_data_stop_vod_task():
    try:
        update_data_stop_vod()
    except Exception as e:
        logger.error(f"Error en update_data_stop_vod_task: {e}")
        raise

@shared_task
def update_data_end_vod_task():
    try:
        update_data_end_vod()
    except Exception as e:
        logger.error(f"Error en update_data_end_vod_task: {e}")
        raise
