import pydivert
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

# Создаем фильтр (например, для HTTP трафика)
filter = "tcp.DstPort == 443"


def get_hostname(ip_address):
    try:
        # Выполняем обратный DNS-запрос
        result = dns.resolver.resolve_address(ip_address)
        return str(result[0])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None  # Если нет ответа
    except Exception as e:
        print(f"Ошибка при получении hostname для {ip_address}: {e}")
        return None


# Запускаем дивертер
with pydivert.WinDivert(filter) as w:
    print("Запуск дивертора...")

    for packet in w:
        # if b"Host:" in packet.payload:
        # print(f"Пакет: {packet.dst_addr}")
        print(get_hostname(packet.dst_addr))
        # Пример изменения пакета (если нужно)
        # packet.payload = ...

        w.send(packet)  # Отправляем пакет обратно
