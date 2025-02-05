import pydivert
import dns.resolver
import datetime as dt


def get_func_time(func):
    """Декоратор для измерения времени выполнения функции"""
    def wrapper(*args, **kwargs):
        start = dt.datetime.now()
        res = func(*args, **kwargs)
        end = dt.datetime.now()
        time = end - start
        print(f"Время выполнения {(time.seconds * 10 ** 6) + time.microseconds} микросекунд")
        return res

    return wrapper


# Создаем фильтр, в данном случае для всех tcp запросов через https
filter = "tcp.DstPort == 443"


@get_func_time
def get_hostname(ip_address: str) -> str or None:
    """Функция для получения имени хоста по ip адрессу"""
    try:
        # Выполняем обратный DNS-запрос
        result = dns.resolver.resolve_address(ip_address)
        return str(result[0])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None  # Если нет ответа
    except Exception as e:
        print(f"Ошибка при получении hostname для {ip_address}: {e}")
        return None


def firewall():
    """Основная функция для работы всей программы"""
    # Запускаем WinDivert
    with pydivert.WinDivert(filter) as w:
        print("Запуск...")
        for packet in w:
            # print(f"Пакет: {packet}")

            # host = socket.gethostbyaddr((packet.dst_addr))
            host = get_hostname(packet.dst_addr)
            print(packet.dst_addr, host)
            # if host and ".ru" in host:
            #    continue

            w.send(packet)  # Отправляем пакет обратно


if __name__ == "__main__":
    firewall()
