# Облачный образ как запасной способ поднять машины стенда (006)

В некоторых средах Hyper-V автоустановка Ubuntu (subiquity) из ISO зависает на шаге установки
загрузчика (`installing missing packages` / grub-efi) — это не чинится настройкой автоустановки
(проверено: пакеты, полный образ, IPv6, зеркало, MTU, внешний коммутатор, Secure Boot, DNS).
Причём apt на уже **загруженной** системе работает — виснет именно установщик.

Запасной путь — **облачный образ** Ubuntu (уже установленная система, никакого установщика):

1. Скачать generic cloud image (qcow2):
   `https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img`
2. Конвертировать в VHDX (нужен `qemu-img`; портативный — `cloudbase.it/downloads/qemu-img-win-x64-2_3_0.zip`):
   `qemu-img convert -f qcow2 -O vhdx noble-cloudimg.img mlsiem-<role>-cloud.vhdx`
3. Собрать cloud-init NoCloud seed (обычный cloud-config, НЕ autoinstall) из `configs/stream.yaml`:
   `uv run python stand/cloud/build_cloud_seed.py victim|attacker` → `var/stand/seed-cloud-<role>.iso`
4. Создать Gen2-ВМ прямо на этом VHDX (диск-загрузчик, без DVD-установки), подключить seed как
   DVD, расширить диск `Resize-VHD ... 10GB` (cloud-init растянет раздел сам), Secure Boot Off,
   адаптеры lab (в `mlsiem-lab`, MAC из `lab.lab_mac`) и install (в сеть с интернетом), для
   атакующего — ещё COM-порт `\\.\pipe\mlsiem-attacker-com1`. Подробные команды — в истории
   сессии и в [[ml-siem-v2-006-live-acceptance]] (память).

Seed кладёт то же, что и автоустановочный (`stand/broker/user-data-*.yaml.j2`): пользователей,
статический адрес стенда, службы жертвы / инструменты атакующего (ставятся apt на первой
загрузке), раннер сценариев на COM-порту. DNS жёстко 8.8.8.8/1.1.1.1, apt — ForceIPv4.
