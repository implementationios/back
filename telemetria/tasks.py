from celery import shared_task
from .views import TestFetchAndStoreTelemetryDataView, UpdateDataOTT, UpdateDataDVB, UpdateDataEndCatchup, UpdateDataStopVOD, UpdateDataEndVOD

@shared_task
def test_fetch_store_telemetry():
    view = TestFetchAndStoreTelemetryDataView()
    request = None  # Puede que necesites construir un request adecuado aquí
    view.post(request)

@shared_task
def update_data_ott():
    view = UpdateDataOTT()
    request = None
    view.post(request)

@shared_task
def update_data_dvb():
    view = UpdateDataDVB()
    request = None
    view.post(request)

@shared_task
def update_data_end_catchup():
    view = UpdateDataEndCatchup()
    request = None
    view.post(request)

@shared_task
def update_data_stop_vod():
    view = UpdateDataStopVOD()
    request = None
    view.post(request)

@shared_task
def update_data_end_vod():
    view = UpdateDataEndVOD()
    request = None
    view.post(request)
