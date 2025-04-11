📦 Cambios en TestFetchAndStoreTelemetry y Funciones Relacionadas (Versión 1.0)
🧠 Objetivo
Optimizar el almacenamiento de registros de telemetría provenientes del sistema CV en el modelo Telemetria, reduciendo el uso de memoria y evitando errores por exceso de variables SQL (como el error too many SQL variables y el error R14 en Heroku).

📌 Vista Modificada: TestFetchAndStoreTelemetry
✅ ¿Qué hacía antes?
Hacía login contra el sistema CV.

Obtenía todos los registros o solo nuevos según si la base estaba vacía.

Insertaba todos los registros de forma no fragmentada.

No contaba con control preciso de memoria o de registros existentes.

🔁 Cambios Realizados
División del almacenamiento en "chunks" y "batches":

Se dividió la lógica en bloques de:

chunk_size = 100 (para verificar existencia de recordIds).

batch_size = 500 (para guardar en DB).

Esto reduce carga de memoria y mejora el rendimiento.

Uso de bulk_create con ignore_conflicts=True:

Inserta múltiples registros a la vez sin lanzar errores por duplicados.

Validación individual con serializer.is_valid() para datos antes de guardar.

Solo datos válidos llegan al modelo.

Manejo detallado de errores por registro inválido, errores de timestamp, etc.

Mejora trazabilidad de fallos individuales.

Control de duplicados mediante recordId y solo inserción de nuevos registros.

📌 Funciones Relacionadas
1. store_telemetry_data(data_batch)
💡 Responsabilidad: Insertar registros nuevos en bloques, verificando duplicados previamente.

✅ Ventajas actuales:

Fragmentación controlada del flujo de datos.

Ahorro de memoria.

Registros inválidos no interrumpen todo el proceso.

❌ Problemas anteriores:

Se podía alcanzar el límite de variables SQL.

Todos los datos se evaluaban de golpe.

No se controlaba duplicación ni validación.

2. extract_timestamp_details(data)
💡 Responsabilidad: Añadir dataDate y timeDate derivados del timestamp.

✅ Ventajas actuales:

Mejora el análisis temporal posterior.

Manejo de errores por timestamp inválido por registro.

❌ Problemas anteriores:

No existía preprocesamiento del timestamp.

Timestamp malformado podía romper el flujo completo.

3. fetch_and_store_data_streaming(client, limit)
💡 Responsabilidad: Obtener todos los registros en streaming paginado.

✅ Ventajas actuales:

Se consulta en páginas (offset, limit).

Evita cargar todos los datos en memoria.

❌ Problemas anteriores:

No había paginación o estaba mal utilizada (potencial error R14).

Posible cuelgue en sistemas con grandes volúmenes de datos.

4. fetch_data_up_to(client, highestRecordId, limit)
💡 Responsabilidad: Descargar nuevos registros hasta el último recordId guardado.

✅ Ventajas actuales:

Ahorra tiempo y peticiones.

Se detiene una vez alcanzado el recordId ya existente.

❌ Problemas anteriores:

El sistema volvía a procesar todos los datos aunque ya existieran.

5. is_database_empty()
💡 Responsabilidad: Verificar si la tabla Telemetria está vacía.

🔧 Uso: Determina si se debe hacer descarga total o incremental.

🔄 Refactor: Funciones de Fusión y Almacenamiento (UpdateData*) — Versión 1.0
📌 Vistas Incluidas
UpdateDataOTT

UpdateDataDVB

UpdateDataStopCatchup

UpdateDataEndCatchup

UpdateDataStopVOD

UpdateDataEndVOD

🎯 Objetivo del Cambio
Reestructurar y optimizar las vistas encargadas de fusionar registros de eventos (Telemetria) en sus respectivas tablas de datos procesados (MergedTelemetric*), evitando sobrecarga de memoria o errores como el R14 en Heroku, y asegurando una ejecución segura, validada y escalable.

⚙️ Cambios Comunes Aplicados a Todas las Vistas
Funcionalidad	Antes	Después
🔁 Fusión de datos (dataName)	Se hacía en memoria, sin separación clara	Fusiona dataName de registros actionId=x solo si dataName está vacío
🧠 Validación de datos	Cero validación: se pasaban datos crudos a los modelos	Se filtran campos con get_valid_fields() antes de crear instancias
🧵 Inserción en DB	bulk_create() sin control de memoria	bulk_create() por lotes de batch_size=100
🧼 Filtrado de duplicados	No se verificaba si el registro ya existía	Se filtran solo registros con recordId mayores al último existente
📛 Manejo de errores	Generalizado (catch-all) y sin logs	Logs por ValidationError, IntegrityError y Exception específicos
🗃️ Estructura de la Fusión
Todas estas clases siguen el patrón:

Obtener registros de Telemetria con actionId específicos.

Mapear dataId -> dataName desde el actionId "referencia".

Fusionar si dataName está vacío.

Insertar nuevos registros en MergedTelemetric* si recordId > último guardado.

📍 Descripción Individual
🔹 UpdateDataOTT
Fusión: actionId=8 obtiene dataName de actionId=7.

Tabla destino: MergedTelemetricOTT

🔹 UpdateDataDVB
Fusión: actionId=6 hereda dataName de actionId=5.

Tabla destino: MergedTelemetricDVB

🔹 UpdateDataStopCatchup
Fusión: actionId=17 toma dataName de actionId=16.

Tabla destino: MergedTelemetricStopCatchup

🔹 UpdateDataEndCatchup
Fusión: actionId=18 hereda dataName de actionId=16.

Tabla destino: MergedTelemetricEndCatchup

🔹 UpdateDataStopVOD
Fusión: actionId=14 toma dataName de actionId=13.

Tabla destino: MergedTelemetricStopVOD

🔹 UpdateDataEndVOD
Fusión: actionId=15 se empareja con actionId=13 por dataId.

Tabla destino: MergedTelemetricEndVOD

⚠️ Desventajas de la Versión Anterior
Problema	Impacto
Falta de validación de campos	Inserción de datos erróneos y posibles errores de serialización
Carga masiva en memoria	Riesgo de R14 / out-of-memory en servidores como Heroku
Sin control de duplicados	Reintentos forzaban inserciones duplicadas
Código repetido sin modularización	Mayor dificultad para mantener y escalar
✅ Beneficios de la Versión Actual
🧠 Más segura: validación campo por campo.

📦 Más eficiente: procesamiento por lotes pequeños.

🔁 Más confiable: inserción idempotente y sin duplicación.

🧩 Lista para escalado: si hay millones de registros, sigue funcionando.

🧾 Loguea errores para debug posterior.


📊 Análisis Diario de OTT – TelemetriaDaysOTT
Versión: 1.0

🎯 Objetivo del Cambio
Optimizar el análisis estadístico de los registros OTT (MergedTelemetricOTT) para prevenir errores de memoria (como el R14 en Heroku), evitando el uso innecesario de recursos y mejorando la legibilidad del código. Se incluyó documentación, estructura modular, validaciones y control sobre el tamaño de los datos utilizados.

🧠 Problemas de la versión anterior
Problema	Impacto
❌ Uso completo de .all()	Traía todos los registros a memoria sin importar el tamaño de la DB
❌ Código duplicado	Cada método filtraba por días manualmente
❌ Sin documentación ni control	Era difícil mantener y escalar
❌ No había separación de lógica	Mezclaba lógica de filtrado, cálculo y serialización
❌ Sin modularidad en franjas	Cada función repetía la estructura de filtrado por franja
✅ Mejoras de la versión 1.0
Mejora	Detalle
🔃 get_filtered_data(days) centralizado	Función única para evitar repetición en cada función
🧠 Modularización total	Cada función tiene una única responsabilidad clara
📊 Franjas horarias reutilizadas	Se aplican franjas compartidas en todas las funciones de análisis
🧼 Filtrado eficiente	.filter(...).iterator() puede aplicarse fácilmente si se requiere
📎 Documentación completa por función	Cada función indica su uso, parámetros y retorno
💾 Ahorro de memoria	Se evita almacenar listas innecesarias (especialmente para gráficos)
📂 Funcionalidades implementadas
Función	Descripción
get_filtered_data(days)	Devuelve registros filtrados por los últimos n días, o todos si days <= 0.
dataRangeOTT(days)	Calcula la duración total de todos los registros en el rango dado (en horas).
franjaHorarioOTT(days)	Suma la duración por franjas horarias (Madrugada, Mañana, Tarde, Noche) + gráfico de torta.
listEventOTT(days)	Suma la duración por tipo de evento (dataName).
listCountEventOTT(days)	Cuenta la cantidad de eventos por dataName.
graphOTT(days)	Genera un gráfico de barras y líneas de horas vs cantidad de eventos, por canal.
franjaHorarioEventOTT{Franja}	Filtra duración por tipo de evento en una franja específica.
listCountEventOTT{Franja}	Cuenta eventos por canal en una franja horaria específica.
graphOTT{Franja}	Genera gráfico combinado de barras y líneas para la franja dada.
get(request, days)	Endpoint principal. Devuelve todos los análisis y gráficos, agrupados por sección.
📦 Estructura del JSON de Respuesta
json
Copiar
Editar
{
  "totals": {
    "totaldurationott": { ... },
    "franjahorariaott": { ... },
    "franjahorariaeventottmadrugada": { ... },
    "countchannelsmadrugada": { ... },
    "franjahorariaeventottmañana": { ... },
    "countchannelsmañana": { ... },
    "franjahorariaeventotttarde": { ... },
    "countchannelstarde": { ... },
    "franjahorariaeventottnoche": { ... },
    "countchannelsnoche": { ... }
  },
  "events": {
    "listOTT": { ... },
    "listCountEventOTT": { ... }
  },
  "graphs": {
    "graphott": { "graph": "<plotly_json>" },
    "graphottMadrugada": { "graph": "<plotly_json>" },
    "graphottMañana": { "graph": "<plotly_json>" },
    "graphottTarde": { "graph": "<plotly_json>" },
    "graphottNoche": { "graph": "<plotly_json>" }
  }
}
🚧 Consideraciones Técnicas
Todas las funciones trabajan con MergedTelemetricOTT.

En caso de error, los métodos devuelven None o un diccionario {"error": mensaje}.

Los gráficos están codificados en formato JSON Plotly para frontend interactivo.

Las franjas horarias son fijas y compartidas entre funciones.