# Runtime Scripts

Здесь оставлены только скрипты, нужные для запуска и проверки прототипа:

- `start_system.ps1` - локальный запуск инфраструктуры, Worker replay, Alerts и API/dashboard.
- `start_system_docker.ps1` - запуск demo profile через Docker Compose.
- `init_clickhouse.py` - применение ClickHouse schema.
- `run_e2e_smoke.py` - end-to-end smoke runtime path.

Скрипты обучения, подготовки датасетов, evaluation и calibration experiments вынесены в `offline-training/scripts/`.
