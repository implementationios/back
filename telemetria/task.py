from celery import shared_task
from celery.schedules import crontab
from telemetria.views import MergedTelemetricData  # Ajusta la importación según la ubicación real
from .models import MergedTelemetricActionId8

@shared_task
@celery.schedules.crontab(minute='02', hour='19')
def DataActionId8(request):
    new_records = []
    try:
        merged_data = MergedTelemetricData.filterAndSumData()
        for i in merged_data:
            # Crear el existing_record dentro del bucle
            existing_record = MergedTelemetricActionId8.objects.filter(recordId=i.get('recordId')).first()
            # Verificar si el registro ya existe
            if existing_record:
                # Si el registro ya existe, continua con el próximo elemento en merged_data
                continue
            # Si el registro no existe, crea una nueva instancia de MergedTelemetricActionId8
            new_record = MergedTelemetricActionId8(
                actionId=i.get('actionId'),
                actionKey=i.get('actionKey'),
                anonymized=i.get('anonymized'),
                data=i.get('data'),
                dataDuration=i.get('dataDuration'),
                dataId=i.get('dataId'),
                dataName=i.get('dataName'),
                dataNetId=i.get('dataNetId'),
                dataPrice=i.get('dataPrice'),
                dataSeviceId=i.get('dataSeviceId'),
                dataTsId=i.get('dataTsId'),
                date=i.get('date'),
                deviceId=i.get('deviceId'),
                ip=i.get('ip'),
                ipId=i.get('ipId'),
                manual=i.get('manual'),
                profileId=i.get('profileId'),
                reaonId=i.get('reaonId'),
                reasonKey=i.get('reasonKey'),
                recordId=i.get('recordId'),
                smartcardId=i.get('smartcardId'),
                subscriberCode=i.get('subscriberCode'),
                timestamp=i.get('timestamp'),
                dataDate=i.get('dataDate'),
                timeDate=i.get('timeDate'),
                whoisCountry=i.get('whoisCountry'),
                whoisIsp=i.get('whoisIsp')
            )
            # Agregar la nueva instancia a la lista
            new_records.append(new_record)
        # Crear las nuevas instancias en la base de datos
        MergedTelemetricActionId8.objects.bulk_create(new_records)
    except Exception as e:
        raise e