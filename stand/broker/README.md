# Шаблоны брокерной машины (фича 005)

Из этих шаблонов и `configs/stream.yaml` команда `uv run mlsiem stand seed-iso` собирает
seed-ISO автоустановки (`var/stand/seed.iso`, метка тома `CIDATA`). Руками готовые файлы не
правят: поменяйте шаблон или конфиг и пересоберите образ — сборка детерминирована.

| Файл | Что это |
|---|---|
| `user-data.yaml.j2` | autoinstall Ubuntu Server 24.04: сеть (статический адрес служебной сети по MAC, DHCP на установочном адаптере), SSH только по ключу, пакеты (`openjdk-21-jre-headless`, `ufw`), а в разделе `user-data` — пользователь и файлы для первой загрузки |
| `meta-data.j2` | идентификатор экземпляра cloud-init |
| `server.properties.j2` | Kafka в режиме KRaft combined: `process.roles=broker,controller`, клиенты на `<broker_ip>:9092`, контроллер на `127.0.0.1:9093`, `auto.create.topics.enable=false` |
| `kafka.service.j2` | служба systemd от пользователя `kafka`, куча JVM из `stand.kafka_heap_mb` |
| `install-kafka.sh.j2` | первая загрузка: архив Kafka с downloads.apache.org и проверка SHA-512, пользователь `kafka`, `kafka-storage.sh format` с фиксированным cluster id, ufw, служба, топики |

Порядок запуска и ресурсы — в `../hyperv/README.md`.

Обновить Kafka: поменять `stand.kafka_version` и `stand.kafka_sha512` в `configs/stream.yaml`
(сумма — из `kafka_2.13-<версия>.tgz.sha512` на downloads.apache.org), пересобрать seed-ISO и
пересоздать машину.
