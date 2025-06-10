import subprocess
import re
import socket
import sys
import ipaddress
from typing import Optional, Dict, List, Any
import requests


def get_geo(ip: str) -> Optional[Dict[str, Any]]:
    """Получает информацию о геолокации IP через API."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,as,isp,org", timeout=3)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"[DEBUG] Ошибка при получении геоинфы для {ip}: {e}")
    return None


def perform_traceroute(target: str) -> List[Dict[int, str]]:
    """Выполняет трассировку маршрута и возвращает список хопов."""
    try:
        command = ['tracert', '-d', '-h', '30', '-w', '1000', target] if sys.platform.startswith('win') \
            else ['traceroute', '-m', '30', '-w', '3', '-q', '1', '-n', target]

        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')
        output = result.stdout

        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            target_ip = target

        hops = []
        for line in output.splitlines():
            match = re.search(r'^\s*(\d+)\s+(?:<\d+\.\d+ ms\s+)+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                hop_num, ip = match.groups()
                if ip != target_ip and (not hops or ip != hops[-1]['ip']):
                    hops.append({'hop': int(hop_num), 'ip': ip})

        return hops

    except Exception as e:
        print(f"Ошибка при выполнении трассировки: {e}")
        return []


def is_private_ip(ip: str) -> bool:
    """Проверяет, является ли IP приватным."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_ip_info(ip: str) -> Dict[str, str]:
    """Возвращает информацию об IP-адресе."""
    if is_private_ip(ip):
        return {
            'as': 'Локальная',
            'country': 'N/A',
            'provider': 'Маршрутизатор',
            'org': 'Локальная сеть'
        }

    geo_data = get_geo(ip)
    if not geo_data:
        return {'as': 'N/A', 'country': 'N/A', 'provider': 'N/A', 'org': 'N/A'}

    as_number = geo_data.get('as', 'N/A').split()[0] if geo_data.get('as', 'N/A') != 'N/A' else 'N/A'
    provider = geo_data.get('isp', geo_data.get('org', 'N/A'))
    org = geo_data.get('org', provider)

    return {
        'as': as_number,
        'country': geo_data.get('countryCode', 'N/A'),
        'provider': provider,
        'org': org
    }


def format_cell(text: str, width: int = 15, ellipsis: str = "...") -> str:
    """Форматирует строку под заданную ширину колонки."""
    if len(text) > width:
        return text[:width - len(ellipsis)] + ellipsis
    return text.ljust(width)


def check_internet_connection() -> bool:
    """Проверяет наличие интернет-соединения."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False


def resolve_target(target_input: str) -> Optional[str]:
    """Преобразует доменное имя в IP-адрес."""
    try:
        ipaddress.ip_address(target_input)
        return target_input
    except ValueError:
        try:
            return socket.gethostbyname(target_input)
        except socket.gaierror:
            return None


def main() -> None:
    print("Трассировка маршрута")
    user_input = input("Введите доменное имя или IP-адрес: ").strip()

    if not check_internet_connection():
        print("Ошибка: нет подключения к интернету!")
        return

    resolved_ip = resolve_target(user_input)
    if not resolved_ip:
        print("Ошибка: неверный домен или IP!")
        return

    print("\nВыполняем трассировку...")
    route_hops = perform_traceroute(resolved_ip)
    if not route_hops:
        print("Не удалось выполнить трассировку")
        return

    print("\nРезультаты трассировки:")
    print("№   | IP-адрес       | AS         | Страна | Провайдер")
    print("----|----------------|------------|--------|----------------------------")

    for hop in route_hops:
        hop_number = str(hop['hop']).rjust(3)
        ip = format_cell(hop['ip'], 14)
        info = get_ip_info(hop['ip'])

        asn = format_cell(info['as'], 9)
        country = format_cell(info['country'], 6)
        provider = format_cell(info['provider'], 27)

        print(f"{hop_number} | {ip} | {asn} | {country} | {provider}")


if __name__ == "__main__":
    main()
