from celery.schedules import crontab
from django_celery_beat.models import PeriodicTask, CrontabSchedule

schedule, created = CrontabSchedule.objects.get_or_create(
    minute='0',
    hour='*/6',  # Cada 6 horas
    day_of_week='*',
    day_of_month='*',
    month_of_year='*',
)

PeriodicTask.objects.update_or_create(
    crontab=schedule,
    name='Test fetch and store telemetry data',
    defaults={'task': 'tu_aplicacion.tasks.test_fetch_store_telemetry'},
)

PeriodicTask.objects.update_or_create(
    crontab=schedule,
    name='Update data OTT',
    defaults={'task': 'tu_aplicacion.tasks.update_data_ott'},
)

PeriodicTask.objects.update_or_create(
    crontab=schedule,
    name='Update data DVB',
    defaults={'task': 'tu_aplicacion.tasks.update_data_dvb'},
)

PeriodicTask.objects.update_or_create(
    crontab=schedule,
    name='Update data End Catchup',
    defaults={'task': 'tu_aplicacion.tasks.update_data_end_catchup'},
)

PeriodicTask.objects.update_or_create(
    crontab=schedule,
    name='Update data Stop VOD',
    defaults={'task': 'tu_aplicacion.tasks.update_data_stop_vod'},
)

PeriodicTask.objects.update_or_create(
    crontab=schedule,
    name='Update data End VOD',
    defaults={'task': 'tu_aplicacion.tasks.update_data_end_vod'},
)
