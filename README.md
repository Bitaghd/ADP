# ADP Prototype

Прототип потоковой системы обнаружения аномалий в сетевом трафике.

Runtime-часть построена на .NET 8: Zeek `conn.log` поступает в Collector, далее через Kafka обрабатывается Worker, признаки нормализуются, окна подаются в ONNX-модель CNN-GRU-AE, результаты сохраняются в ClickHouse и отображаются в ASP.NET Core dashboard.

## Что входит в GitHub-версию

- `src/` - .NET runtime-компоненты: API/dashboard, Collector, Worker, Contracts, Features, Windowing, Inference, Storage, Alerts.
- `configs/` - runtime-контракты: схема признаков и пример threshold config.
- `infra/` - ClickHouse schema и Kafka topic bootstrap.
- `scripts/` - только запуск, инициализация и end-to-end smoke для прототипа.
- `docs/` - документация по runtime, Docker, ClickHouse, Zeek и dashboard.
- `models/*.onnx` и небольшой whitelist в `artifacts/` - минимальные файлы для демо-запуска.
- `offline-training/` - отдельно сгруппированный контур подготовки данных, обучения, evaluation и calibration experiments.

Тяжелые datasets, PCAP, parquet/npz, PyTorch checkpoints, runtime logs, `bin/obj`, IDE-каталоги и экспериментальные артефакты исключены через `.gitignore`.

## Быстрый запуск демо

Требования:

- .NET 8 SDK;
- Docker Desktop / Docker Engine с Docker Compose.

Запуск из корня репозитория:

```powershell
docker compose --profile demo up --build
```

Dashboard:

```text
http://localhost:5088/
```

Демо по умолчанию использует:

```text
artifacts/zeek/example/conn.log
models/cnn_gru_ae_example.onnx
artifacts/scalers/example.scaler.json
artifacts/thresholds/example.threshold_config.json
```

## Локальный запуск без полного compose

```powershell
.\scripts\start_system.ps1
```

Смоук-проверка runtime path:

```powershell
python scripts\run_e2e_smoke.py --reset-clickhouse
```

## Live-развертывание

Live-режим читает Zeek JSON `conn.log`, отправляет события в Kafka, обрабатывает их Worker и пишет телеметрию в ClickHouse. По умолчанию Compose ожидает live-лог здесь:

```text
artifacts/zeek/live/conn.log
```

Runtime-артефакты по умолчанию:

```text
models/cnn_gru_ae_example.onnx
artifacts/scalers/example.scaler.json
artifacts/thresholds/example.threshold_config.json
```

### Способ 1: Docker Compose + внешний Zeek

Подходит для Windows, macOS и Linux, если Zeek уже установлен на хосте или на отдельном сенсоре. Zeek должен писать JSON-лог в `artifacts/zeek/live/conn.log`.

```powershell
New-Item -ItemType Directory -Force artifacts\zeek\live | Out-Null
docker compose --profile live up --build
```

Пример запуска Zeek на хосте:

```powershell
zeek -i <interface> -C LogAscii::use_json=T
```

Если Zeek пишет в другой каталог, укажите его перед запуском Compose:

```powershell
$env:ADP_LIVE_ZEEK_DIR="C:\zeek-live"
docker compose --profile live up --build
```

### Способ 2: WSL2 + Zeek в WSL

Подходит для Windows, когда Zeek удобнее запускать внутри WSL2, а инфраструктуру - через Docker Compose из той же WSL-сессии. Команды ниже выполняются в WSL.

```bash
cd /mnt/c/Users/<windows-user>/Desktop/ADP_PROTOTYPE
mkdir -p artifacts/zeek/live
docker compose --profile live up --build
```

В отдельном WSL-терминале запустите Zeek из каталога, который смонтирован в `collector-live`:

```bash
cd /mnt/c/Users/<windows-user>/Desktop/ADP_PROTOTYPE/artifacts/zeek/live
sudo zeek -i eth0 -C LogAscii::use_json=T
```

Для проверки отправляйте HTTP-запросы из WSL или с хоста, чей трафик виден выбранному интерфейсу:

```bash
cd /mnt/c/Users/<windows-user>/Desktop/ADP_PROTOTYPE
python3 scripts/test_live_requests.py --target-url http://test-host.local/ --count 300 --concurrency 12
```

Dashboard будет доступен в Windows-браузере:

```text
http://localhost:5088/
```

### Способ 3: Docker Compose + Zeek container

Подходит для Linux-хоста, где контейнеру можно дать `network_mode: host` и `NET_ADMIN`/`NET_RAW`. Интерфейс задается через `ADP_ZEEK_INTERFACE`.

```bash
ADP_ZEEK_INTERFACE=eth0 docker compose --profile live --profile zeek-live up --build
```

Dashboard будет доступен на:

```text
http://localhost:5088/
```

### Способ 4: гибридный запуск для разработки

Инфраструктуру можно оставить в Docker, а Collector, Worker и API запустить локально из исходников.

```powershell
docker compose up -d clickhouse kafka
python scripts\init_clickhouse.py --url http://localhost:8123 --user default --password adp --database default
powershell -ExecutionPolicy Bypass -File infra\kafka\create_topics.ps1
```

Collector:

```powershell
dotnet run --project src\AnomalyDetection.Collector -- `
  --conn-log artifacts\zeek\live\conn.log `
  --follow `
  --from-end `
  --wait-for-file `
  --kafka-bootstrap localhost:9092 `
  --kafka-address-family v4 `
  --topic zeek.conn.raw
```

Worker:

```powershell
dotnet run --project src\AnomalyDetection.Worker -- `
  --kafka-bootstrap localhost:9092 `
  --kafka-topic zeek.conn.raw `
  --kafka-group-id adp-worker-live `
  --kafka-address-family v4 `
  --kafka-idle-timeout-seconds 0 `
  --schema configs\feature_schema.json `
  --scaler artifacts\scalers\example.scaler.json `
  --threshold artifacts\thresholds\example.threshold_config.json `
  --model models\cnn_gru_ae_example.onnx `
  --output artifacts\runtime\local.kafka.detections.jsonl `
  --clickhouse-url http://localhost:8123 `
  --clickhouse-user default `
  --clickhouse-password adp `
  --clickhouse-batch-size 25
```

API/dashboard:

```powershell
dotnet run --project src\AnomalyDetection.Api
```

Для генерации live-трафика можно отправить серию HTTP-запросов на контролируемый тестовый хост, который виден интерфейсу Zeek:

```powershell
python scripts\test_live_requests.py --target-url http://test-host.local/ --count 300 --concurrency 12
```

## Offline training

Контур обучения модели не нужен для запуска прототипа и вынесен в `offline-training/`.
Там лежат Python-скрипты подготовки Zeek-compatible features, windowing, обучения CNN-GRU-AE, экспорта ONNX и evaluation/calibration.

Зависимости Python для этого контура находятся в `offline-training/requirements.txt`.
Выходы offline-процессов должны складываться в `artifacts/` или `offline-training/artifacts/`; они по умолчанию не попадают в Git.

## Полезные документы

- `docs/docker_run.md` - Docker Compose runbook.
- `docs/deployment_full_system.md` - полный deployment с Zeek.
- `docs/traffic_data_processing.md` - обработка трафика до инференса.
- `docs/model_inference_rolling_threshold.md` - ONNX-инференс и threshold.
- `docs/clickhouse_storage.md` - схема и проверки ClickHouse.
