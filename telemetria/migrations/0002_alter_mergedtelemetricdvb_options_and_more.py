# Generated by Django 5.0.7 on 2025-01-17 13:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('telemetria', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='mergedtelemetricdvb',
            options={'verbose_name': 'Telemetría DVB', 'verbose_name_plural': 'Telemetrías DVB'},
        ),
        migrations.AlterModelOptions(
            name='mergedtelemetricendcatchup',
            options={'verbose_name': 'Telemetría End Catchup', 'verbose_name_plural': 'Telemetrías End Catchup'},
        ),
        migrations.AlterModelOptions(
            name='mergedtelemetricendvod',
            options={'verbose_name': 'Telemetría End VOD', 'verbose_name_plural': 'Telemetrías End VOD'},
        ),
        migrations.AlterModelOptions(
            name='mergedtelemetricott',
            options={'verbose_name': 'Telemetría OTT', 'verbose_name_plural': 'Telemetrías OTT'},
        ),
        migrations.AlterModelOptions(
            name='mergedtelemetricstopcatchup',
            options={'verbose_name': 'Telemetría Stop Catchup', 'verbose_name_plural': 'Telemetrías Stop Catchup'},
        ),
        migrations.AlterModelOptions(
            name='mergedtelemetricstopvod',
            options={'verbose_name': 'Telemetría Stop VOD', 'verbose_name_plural': 'Telemetrías Stop VOD'},
        ),
        migrations.AlterModelOptions(
            name='telemetria',
            options={'verbose_name': 'Telemetría', 'verbose_name_plural': 'Telemetrías'},
        ),
    ]
