from django_cron import CronJobBase, Schedule
from .tasks import test_fetch_store_telemetry, update_data_ott, update_data_dvb, update_data_end_catchup, update_data_stop_vod, update_data_end_vod

class TestFetchStoreTelemetryCronJob(CronJobBase):
    RUN_AT_TIMES = ['00:00', '12:00']  # Se ejecuta a las 00:00 y 12:00
    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'telemetria.test_fetch_store_telemetry'  # un código único

    def do(self):
        test_fetch_store_telemetry()

class UpdateDataOttCronJob(CronJobBase):
    RUN_AT_TIMES = ['00:00', '12:00']

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'telemetria.update_data_ott'

    def do(self):
        update_data_ott()

class UpdateDataDvbCronJob(CronJobBase):
    RUN_AT_TIMES = ['00:00', '12:00']

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'telemetria.update_data_dvb'

    def do(self):
        update_data_dvb()

class UpdateDataEndCatchupCronJob(CronJobBase):
    RUN_AT_TIMES = ['00:00', '12:00']

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'telemetria.update_data_end_catchup'

    def do(self):
        update_data_end_catchup()

class UpdateDataStopVodCronJob(CronJobBase):
    RUN_AT_TIMES = ['00:00', '12:00']

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'telemetria.update_data_stop_vod'

    def do(self):
        update_data_stop_vod()

class UpdateDataEndVodCronJob(CronJobBase):
    RUN_AT_TIMES = ['00:00', '12:00']

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'telemetria.update_data_end_vod'

    def do(self):
        update_data_end_vod()
