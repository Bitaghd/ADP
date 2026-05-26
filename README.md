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
artifacts/zeek/wednesday_first_2min/conn.log
models/cnn_gru_ae_wednesday_full.onnx
artifacts/scalers/wednesday_full.scaler.json
artifacts/thresholds/wednesday_full.threshold_config.json
```

## Локальный запуск без полного compose

```powershell
.\scripts\start_system.ps1
```

Смоук-проверка runtime path:

```powershell
python scripts\run_e2e_smoke.py --reset-clickhouse
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
