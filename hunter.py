import asyncio
import json
import logging
import ipaddress
import signal
import sys
import os
import time
import random
import tempfile
import uuid
from dataclasses import dataclass, field
from dotenv import load_dotenv
import aiohttp
from aiohttp_socks import ProxyConnector
from aiogram import Bot, Dispatcher, types, F
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    ReplyKeyboardMarkup, KeyboardButton, BufferedInputFile,
    InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery,
)

# --- [ЗАГРУЗКА .env] ---
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

_required = {'TG_TOKEN', 'ADMIN_ID'}
_missing = [v for v in _required if not os.getenv(v)]
if _missing:
    sys.exit(f"Не заданы переменные окружения: {', '.join(_missing)}\nСкопируй .env.example в .env и заполни значения.")

TG_TOKEN = os.getenv('6531618162:AAG5iytEMV6usf3XqcDKCBuGiS0wNvjphnk')
ADMIN_ID = int(os.getenv('455455922'))
TG_PROXY = os.getenv('TG_PROXY')

# --- КОНСТАНТЫ ---
ALL_REGIONS = ['ru-1', 'ru-2', 'ru-3', 'ru-7', 'ru-8', 'ru-9']
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)
ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.json")
WHITELIST_FILE = os.path.join(DATA_DIR, "whitelist.txt")
if not os.path.exists(WHITELIST_FILE):
    sys.exit(f"Файл whitelist.txt не найден: {WHITELIST_FILE}")

# --- WHITELIST (глобальный, общий для всех аккаунтов) ---
def load_whitelist():
    nets = []
    labels = {}
    with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if " # " in line:
                cidr, label = line.split(" # ", 1)
                net = ipaddress.ip_network(cidr.strip())
                labels[net] = label.strip()
            else:
                net = ipaddress.ip_network(line)
            nets.append(net)
    return nets, sum(n.num_addresses for n in nets), labels

networks, whitelist_total_ips, network_labels = load_whitelist()

# --- УТИЛИТЫ ---
def nearest_whitelist(addr_str):
    try:
        ip_int = int(ipaddress.ip_address(addr_str))
    except (ValueError, TypeError):
        return None
    best_net = None
    best_dist = float('inf')
    for net in networks:
        net_start = int(net.network_address)
        net_end = int(net.broadcast_address)
        if net_start <= ip_int <= net_end:
            return net, 0
        dist = min(abs(ip_int - net_start), abs(ip_int - net_end))
        if dist < best_dist:
            best_dist = dist
            best_net = net
    return best_net, best_dist

def format_distance(dist):
    if dist >= 1_000_000:
        return f"{dist / 1_000_000:.1f}M"
    if dist >= 1_000:
        return f"{dist / 1_000:.1f}K"
    return str(dist)

def estimate_pool_size(total_checks, unique_count):
    if total_checks < 5 or unique_count == 0 or unique_count >= total_checks:
        return None
    lo, hi = float(unique_count), float(unique_count) * 1000
    for _ in range(100):
        mid = (lo + hi) / 2
        expected = mid * (1 - ((mid - 1) / mid) ** total_checks)
        if expected < unique_count:
            lo = mid
        else:
            hi = mid
    return int((lo + hi) / 2)


# ============================================================
#  ACCOUNT — один аккаунт Selectel со своим стейтом и сессией
# ============================================================
@dataclass
class Account:
    id: str
    name: str
    selectel_token: str
    project_id: str
    proxy: str | None = None

    # Настройки (персистентные)
    active_regions: list = field(default_factory=lambda: list(ALL_REGIONS))
    current_batch_size: int = 1
    current_sleep_time: int = 300
    balance_threshold: float = 5.0
    smart_zone_mode: bool = False
    pool_exhaust_threshold: int = 85

    # Runtime (не персистентные)
    is_running: bool = field(default=False, repr=False, init=False)
    _session: aiohttp.ClientSession | None = field(default=None, repr=False, init=False)
    roller_task: asyncio.Task | None = field(default=None, repr=False, init=False)
    balance_readings: list = field(default_factory=list, repr=False, init=False)
    _zone_queue: list = field(default_factory=list, repr=False, init=False)
    exhaust_pardoned: set = field(default_factory=set, repr=False, init=False)

    # Статистика (in-memory, сбрасывается при рестарте)
    stats: dict = field(default_factory=lambda: {"checked": 0, "found": 0, "subnet_counts": {}, "subnet_times": {}}, repr=False, init=False)
    seen_ips: dict = field(default_factory=dict, repr=False, init=False)
    zone_stats: dict = field(default_factory=dict, repr=False, init=False)
    closest_miss: tuple | None = field(default=None, repr=False, init=False)
    found_ips: list = field(default_factory=list, repr=False, init=False)

    @property
    def api_headers(self):
        return {"X-Token": self.selectel_token, "Content-Type": "application/json"}

    # --- HTTP ---
    async def get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            connector = ProxyConnector.from_url(self.proxy) if self.proxy else None
            self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self._session

    async def close_session(self):
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def api_request(self, method, url, max_retries=3, retry_delay=15, **kwargs):
        s = await self.get_session()
        for attempt in range(1, max_retries + 1):
            try:
                async with s.request(method, url, **kwargs) as resp:
                    await resp.read()
                    return resp.status
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logging.warning(f"[{self.name}] Попытка {attempt}/{max_retries} ({url}): {e}")
                if attempt < max_retries:
                    await asyncio.sleep(retry_delay * (2 ** (attempt - 1)) + random.uniform(0, retry_delay))
        return None

    async def api_json(self, method, url, max_retries=3, retry_delay=15, **kwargs):
        s = await self.get_session()
        for attempt in range(1, max_retries + 1):
            try:
                async with s.request(method, url, **kwargs) as resp:
                    data = await resp.json(content_type=None)
                    return resp.status, data
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                logging.warning(f"[{self.name}] Попытка {attempt}/{max_retries} ({url}): {e}")
                if attempt < max_retries:
                    await asyncio.sleep(retry_delay * (2 ** (attempt - 1)) + random.uniform(0, retry_delay))
        return None

    # --- Баланс и прогноз ---
    async def get_balance(self):
        try:
            result = await self.api_json("GET", "https://api.selectel.ru/v3/balances", headers=self.api_headers)
            if result and result[0] == 200:
                for b in result[1].get("data", {}).get("billings", []):
                    if b.get("billing_type") == "primary":
                        return f"{((b.get('balances_values_sum', 0) or 0) / 100):.2f}"
        except Exception as e:
            logging.warning(f"[{self.name}] Ошибка баланса: {e}")
        return "???"

    def track_balance(self, balance_str, checked):
        try:
            bal = float(balance_str)
            self.balance_readings.append((bal, checked, time.time()))
            if len(self.balance_readings) > 1000:
                del self.balance_readings[:-1000]
        except (ValueError, TypeError):
            pass

    def estimate_remaining(self):
        if len(self.balance_readings) < 2:
            return None
        initial_bal = self.balance_readings[0][0]
        start = None
        for i, (bal, chk, ts) in enumerate(self.balance_readings):
            if bal < initial_bal:
                start = self.balance_readings[i - 1] if i > 0 else self.balance_readings[0]
                break
        if start is None:
            return None
        start_bal, start_chk, start_ts = start
        last_bal, last_chk, last_ts = self.balance_readings[-1]
        spent = start_bal - last_bal
        checks = last_chk - start_chk
        hours = (last_ts - start_ts) / 3600
        if spent <= 0 or checks <= 0 or hours <= 0:
            return None
        cost_per_check = spent / checks
        cost_per_hour = spent / hours
        return int(last_bal / cost_per_check), last_bal / cost_per_hour, cost_per_check

    # --- Выбор зоны ---
    def pick_next_zone(self):
        self._zone_queue = [z for z in self._zone_queue if z in self.active_regions]
        if not self._zone_queue:
            self._zone_queue = list(self.active_regions)
            random.shuffle(self._zone_queue)
        return self._zone_queue.pop()

    def pick_best_zone(self):
        unexplored, scored = [], []
        for reg in self.active_regions:
            zs = self.zone_stats.get(reg)
            if not zs or zs["checked"] < 5:
                unexplored.append(reg)
                continue
            z_uniq = len(zs.get("seen_cidrs", {}))
            z_pool = estimate_pool_size(zs["checked"], z_uniq)
            score = max(z_pool - z_uniq, 1) if z_pool else max(z_uniq, 1)
            scored.append((reg, score))
        if unexplored:
            return random.choice(unexplored)
        if scored:
            zones, weights = zip(*scored)
            return random.choices(zones, weights=weights, k=1)[0]
        return self.active_regions[0]

    # --- Очистка IP ---
    async def cleanup_ips(self):
        url = "https://api.selectel.ru/vpc/resell/v2/floatingips"
        headers = self.api_headers
        deleted = failed = 0
        try:
            result = await self.api_json("GET", url, headers=headers)
            if result is None or result[0] != 200:
                return 0
            to_delete = []
            for ip_info in result[1].get("floatingips", []):
                if ip_info.get('project_id') == self.project_id:
                    addr, ip_id = ip_info.get('floating_ip_address'), ip_info.get('id')
                    if addr and ip_id and not any(ipaddress.ip_address(addr) in net for net in networks):
                        to_delete.append((addr, ip_id))
            if to_delete:
                results = await asyncio.gather(
                    *[self.api_request("DELETE", f"https://api.selectel.ru/vpc/resell/v2/floatingips/{ip_id}", headers=headers)
                      for _, ip_id in to_delete], return_exceptions=True)
                for (_, _), r in zip(to_delete, results):
                    if isinstance(r, Exception) or r not in (200, 204):
                        failed += 1
                    else:
                        deleted += 1
        except Exception as e:
            logging.error(f"[{self.name}] cleanup_ips: {e}")
        if failed:
            logging.warning(f"[{self.name}] cleanup_ips: {failed} IP не удалено")
        return deleted

    # --- Основной цикл ---
    async def run_roller(self):
        headers = self.api_headers
        while True:
            if not self.is_running or not self.active_regions:
                await asyncio.sleep(5)
                continue

            reg = self.pick_best_zone() if (self.smart_zone_mode and len(self.active_regions) > 1) else self.pick_next_zone()
            batch_checked = []
            batch_nw = {}

            logging.info(f"[{self.name}] --- ЦИКЛ ({reg}) ---")
            url = f"https://api.selectel.ru/vpc/resell/v2/floatingips/projects/{self.project_id}"
            payload = {"floatingips": [{"region": reg, "quantity": 1}]}

            try:
                ips = []
                stop_reason = None
                results = await asyncio.gather(
                    *[self.api_json("POST", url, headers=headers, json=payload) for _ in range(self.current_batch_size)],
                    return_exceptions=True)

                for r in results:
                    if isinstance(r, Exception):
                        logging.error(f"[{self.name}][{reg}] Ошибка создания IP: {r}")
                    elif r is None:
                        logging.error(f"[{self.name}][{reg}] Не удалось создать IP")
                    elif r[0] in (200, 201):
                        ips.extend(r[1].get("floatingips", []))
                    elif r[0] in (401, 403):
                        stop_reason = ("auth", r[0])
                    elif r[0] == 429:
                        stop_reason = ("rate_limit",)
                    else:
                        logging.warning(f"[{self.name}][{reg}] API {r[0]}")

                # Ошибка авторизации
                if stop_reason and stop_reason[0] == "auth":
                    if ips:
                        await asyncio.gather(
                            *[self.api_request("DELETE", f"https://api.selectel.ru/vpc/resell/v2/floatingips/{i.get('id')}", headers=headers)
                              for i in ips if i.get('id')], return_exceptions=True)
                    self.is_running = False

                    try:
                        await bot.send_message(ADMIN_ID,
                            f"[{self.name}] 🔑 <b>Ошибка авторизации ({stop_reason[1]})</b>\n📍 {reg}\n\n<i>Проверь SELECTEL_TOKEN.</i>",
                            parse_mode="HTML")
                    except Exception:
                        pass
                    continue

                # Rate limit
                if stop_reason and stop_reason[0] == "rate_limit":
                    try:
                        await bot.send_message(ADMIN_ID,
                            f"[{self.name}] ⚠️ <b>Rate limit (429)!</b>\n📍 {reg}\n⏳ Пауза 10 мин...", parse_mode="HTML")
                    except Exception:
                        pass
                    if ips:
                        await asyncio.gather(
                            *[self.api_request("DELETE", f"https://api.selectel.ru/vpc/resell/v2/floatingips/{i.get('id')}", headers=headers)
                              for i in ips if i.get('id')], return_exceptions=True)
                    elapsed = 0
                    while elapsed < 600 and self.is_running:
                        await asyncio.sleep(1)
                        elapsed += 1
                    continue

                if not ips:
                    await asyncio.sleep(5)
                    continue

                # Фаза 1: проверка
                good_ips, to_delete = [], []
                for ip_info in ips:
                    addr = ip_info.get('floating_ip_address')
                    if not addr:
                        continue
                    batch_checked.append(addr)
                    self.stats["checked"] += 1
                    self.seen_ips[addr] = self.seen_ips.get(addr, 0) + 1
                    if reg not in self.zone_stats:
                        self.zone_stats[reg] = {"checked": 0, "seen_ips": {}, "seen_cidrs": {}}
                    zs = self.zone_stats[reg]
                    zs["checked"] += 1
                    zs["seen_ips"][addr] = zs["seen_ips"].get(addr, 0) + 1

                    nw = nearest_whitelist(addr)
                    batch_nw[addr] = nw
                    if nw and 0 < nw[1] < 65536:
                        if self.closest_miss is None or nw[1] < self.closest_miss[2]:
                            self.closest_miss = (addr, str(nw[0]), nw[1])

                    try:
                        subnet = str(ipaddress.ip_network(f"{addr}/24", strict=False))
                        self.stats["subnet_counts"][subnet] = self.stats["subnet_counts"].get(subnet, 0) + 1
                        self.stats["subnet_times"][subnet] = time.time()
                        zs["seen_cidrs"][subnet] = zs["seen_cidrs"].get(subnet, 0) + 1
                    except Exception:
                        pass

                    if any(ipaddress.ip_address(addr) in net for net in networks):
                        good_ips.append(addr)
                    else:
                        to_delete.append(ip_info)

                # Фаза 2: удаление промахов
                if to_delete:
                    del_res = await asyncio.gather(
                        *[self.api_request("DELETE", f"https://api.selectel.ru/vpc/resell/v2/floatingips/{i.get('id')}", headers=headers)
                          for i in to_delete], return_exceptions=True)
                    for ip_info, r in zip(to_delete, del_res):
                        if isinstance(r, Exception) or r not in (200, 204):
                            logging.error(f"[{self.name}] Не удалено: {ip_info.get('floating_ip_address')}")

                # Фаза 3: найденные IP
                if good_ips:
                    self.stats["found"] += len(good_ips)
                    now = time.time()
                    for addr in good_ips:
                        label = None
                        for net, lbl in network_labels.items():
                            if ipaddress.ip_address(addr) in net:
                                label = lbl
                                break
                        self.found_ips.append({"ip": addr, "region": reg, "time": now, "label": label})

                    self.is_running = False
                    deleted = await self.cleanup_ips()
                    ip_lines = []
                    for fi in self.found_ips[-len(good_ips):]:
                        line = f"  - <code>{fi['ip']}</code>"
                        if fi.get("label"):
                            line += f" · {fi['label']}"
                        ip_lines.append(line)
                    ips_list = "\n".join(ip_lines)
                    try:
                        await bot.send_message(ADMIN_ID,
                            f"[{self.name}] ✅ <b>НАЙДЕН{'О' if len(good_ips) > 1 else ''}!</b> ({len(good_ips)} шт.)\n\n"
                            f"🌐 <b>IP:</b>\n{ips_list}\n📍 <b>Регион:</b> {reg}\n🧹 <b>Очищено:</b> {deleted}",
                            parse_mode="HTML")
                    except Exception:
                        pass

            except Exception as e:
                logging.error(f"[{self.name}][{reg}] Ошибка: {e}")
                try:
                    await bot.send_message(ADMIN_ID, f"[{self.name}] ⚠️ <b>Ошибка</b>\n📍 {reg}\n<code>{e}</code>", parse_mode="HTML")
                except Exception:
                    pass

            if not self.is_running:
                continue

            balance_text = await self.get_balance()
            self.track_balance(balance_text, self.stats["checked"])

            # Автостоп по балансу
            try:
                bal_float = float(balance_text)
                if self.balance_threshold > 0 and bal_float <= self.balance_threshold:
                    self.is_running = False
                    deleted = await self.cleanup_ips()
                    await bot.send_message(ADMIN_ID,
                        f"[{self.name}] 🛑 <b>Автостоп!</b>\n\n"
                        f"💳 Баланс <b>{balance_text} ₽</b> ≤ порог <b>{self.balance_threshold:.0f} ₽</b>\n"
                        f"📦 Проверено: {self.stats['checked']}\n🧹 Очищено: {deleted}",
                        parse_mode="HTML")

                    continue
            except (ValueError, TypeError):
                pass

            # Авто-исключение зоны
            if self.pool_exhaust_threshold > 0:
                zs = self.zone_stats.get(reg)
                if zs and zs["checked"] >= 20:
                    z_uniq_cidrs = len(zs.get("seen_cidrs", {}))
                    z_repeat_pct = round((1 - z_uniq_cidrs / zs["checked"]) * 100)
                    if z_repeat_pct >= self.pool_exhaust_threshold and reg in self.active_regions and reg not in self.exhaust_pardoned:
                        self.active_regions.remove(reg)
                        try:
                            await bot.send_message(ADMIN_ID,
                                f"[{self.name}] ⚠️ <b>Зона {reg} исключена:</b> {z_repeat_pct}% повторов /24",
                                parse_mode="HTML")
                        except Exception:
                            pass
                        if not self.active_regions:
                            self.is_running = False
                            deleted = await self.cleanup_ips()
                            try:
                                await bot.send_message(ADMIN_ID,
                                    f"[{self.name}] 🛑 <b>Все зоны исчерпаны!</b>\n"
                                    f"📦 Проверено: {self.stats['checked']}\n🧹 Очищено: {deleted}",
                                    parse_mode="HTML")
                            except Exception:
                                pass
        
                            continue

            # Отчёт
            sleep_val = self.current_sleep_time // 60 if self.current_sleep_time >= 60 else self.current_sleep_time
            sleep_unit = "мин" if self.current_sleep_time >= 60 else "сек"
            ips_lines = []
            for ip in batch_checked:
                cnt = self.seen_ips.get(ip, 0)
                tag = f"  🔁 ×{cnt}" if cnt > 1 else ""
                ips_lines.append(f"  - <code>{ip}</code>{tag}")
            ip_line = f"📍 <b>{reg}</b> · {len(batch_checked)} IP:\n" + "\n".join(ips_lines)

            dist_tag = ""
            best_nw = None
            for bip in batch_checked:
                nw = batch_nw.get(bip)
                if nw and nw[1] > 0 and (best_nw is None or nw[1] < best_nw[1]):
                    best_nw = nw
            if best_nw and best_nw[1] < 65536:
                dist_tag = f"\n📐 {format_distance(best_nw[1])} IP до {best_nw[0]}"

            forecast_tag = ""
            est = self.estimate_remaining()
            if est:
                rem_checks, rem_hours, _ = est
                t = f"{rem_hours / 24:.1f}дн" if rem_hours >= 24 else f"{rem_hours:.1f}ч"
                forecast_tag = f"\n🔮 ~{rem_checks} ост. (~{t})"

            report = (
                f"[{self.name}] {ip_line}{dist_tag}\n\n"
                f"📦 {self.stats['checked']} (уник: {len(self.seen_ips)}) · 💰 {balance_text} ₽"
                f"{forecast_tag}\n⏳ <i>{sleep_val} {sleep_unit}...</i>"
            )
            try:
                await bot.send_message(ADMIN_ID, report, parse_mode="HTML")
            except Exception as e:
                logging.error(f"[{self.name}] Ошибка отчёта: {e}")

            # Дробный сон
            elapsed = 0
            while elapsed < self.current_sleep_time and self.is_running:
                await asyncio.sleep(1)
                elapsed += 1


# ============================================================
#  ACCOUNT MANAGER — CRUD + персистентность аккаунтов
# ============================================================
class AccountManager:
    def __init__(self):
        self.accounts: dict[str, Account] = {}

    def add(self, name, token, project_id, proxy=None) -> Account:
        acc_id = uuid.uuid4().hex[:6]
        while acc_id in self.accounts:
            acc_id = uuid.uuid4().hex[:6]
        acc = Account(id=acc_id, name=name, selectel_token=token, project_id=project_id, proxy=proxy)
        self.accounts[acc_id] = acc
        return acc

    def remove(self, acc_id: str) -> Account | None:
        return self.accounts.pop(acc_id, None)

    def get(self, acc_id: str) -> Account | None:
        return self.accounts.get(acc_id)

    def list_all(self) -> list[Account]:
        return list(self.accounts.values())

    def save(self):
        data = [{
            "id": a.id, "name": a.name, "selectel_token": a.selectel_token,
            "project_id": a.project_id, "proxy": a.proxy,
            "active_regions": a.active_regions, "current_batch_size": a.current_batch_size,
            "current_sleep_time": a.current_sleep_time, "balance_threshold": a.balance_threshold,
            "smart_zone_mode": a.smart_zone_mode, "pool_exhaust_threshold": a.pool_exhaust_threshold,
        } for a in self.accounts.values()]
        try:
            fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                os.replace(tmp, ACCOUNTS_FILE)
            except BaseException:
                os.unlink(tmp)
                raise
        except Exception as e:
            logging.error(f"Ошибка сохранения accounts: {e}")

    def load(self):
        if not os.path.exists(ACCOUNTS_FILE):
            return False
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                acc = Account(
                    id=item["id"], name=item["name"],
                    selectel_token=item["selectel_token"], project_id=item["project_id"],
                    proxy=item.get("proxy"),
                    active_regions=item.get("active_regions", list(ALL_REGIONS)),
                    current_batch_size=item.get("current_batch_size", 1),
                    current_sleep_time=item.get("current_sleep_time", 300),
                    balance_threshold=item.get("balance_threshold", 5.0),
                    smart_zone_mode=item.get("smart_zone_mode", False),
                    pool_exhaust_threshold=item.get("pool_exhaust_threshold", 85),
                )
                self.accounts[acc.id] = acc
            logging.info(f"Загружено аккаунтов: {len(self.accounts)}")
            return True
        except Exception as e:
            logging.error(f"Ошибка загрузки accounts: {e}")
            return False

    def ensure_roller(self, acc: Account):
        if acc.roller_task is None or acc.roller_task.done():
            acc.roller_task = asyncio.create_task(acc.run_roller())
            acc.roller_task.add_done_callback(
                lambda t, n=acc.name: logging.error(f"[{n}] roller: {t.exception()}") if not t.cancelled() and t.exception() else None)

    async def start_account(self, acc: Account):
        if acc.is_running:
            return
        acc.is_running = True
        acc.exhaust_pardoned.clear()
        acc._zone_queue.clear()
        self.ensure_roller(acc)

    async def stop_account(self, acc: Account):
        acc.is_running = False


# ============================================================
#  BOT
# ============================================================
tg_session = AiohttpSession(proxy=TG_PROXY) if TG_PROXY else None
bot = Bot(token=TG_TOKEN, session=tg_session)
dp = Dispatcher(storage=MemoryStorage())
manager = AccountManager()

# --- FSM ---
class AddAccountFSM(StatesGroup):
    waiting_name = State()
    waiting_token = State()
    waiting_project_id = State()
    waiting_proxy = State()

class EditProxyFSM(StatesGroup):
    waiting_proxy = State()

# --- КЛАВИАТУРЫ ---
def get_main_kb():
    return ReplyKeyboardMarkup(keyboard=[
        [KeyboardButton(text="👥 Аккаунты"), KeyboardButton(text="📋 Подсети")],
    ], resize_keyboard=True)

def get_accounts_kb():
    kb = []
    for acc in manager.list_all():
        emoji = "🟢" if acc.is_running else "🟡"
        kb.append([InlineKeyboardButton(text=f"{emoji} {acc.name}", callback_data=f"{acc.id}:panel")])
    kb.append([InlineKeyboardButton(text="➕ Добавить аккаунт", callback_data="add_account")])
    return InlineKeyboardMarkup(inline_keyboard=kb)

def get_account_panel_kb(acc: Account):
    btn = InlineKeyboardButton(text="⏸ Остановить", callback_data=f"{acc.id}:stop") if acc.is_running \
        else InlineKeyboardButton(text="🚀 Запустить", callback_data=f"{acc.id}:start")
    proxy_label = acc.proxy[:30] + "…" if acc.proxy and len(acc.proxy) > 30 else (acc.proxy or "нет")
    return InlineKeyboardMarkup(inline_keyboard=[
        [btn],
        [InlineKeyboardButton(text="📊 Статус", callback_data=f"{acc.id}:status")],
        [InlineKeyboardButton(text="⚙️ Настройки", callback_data=f"{acc.id}:settings")],
        [InlineKeyboardButton(text="📥 Экспорт", callback_data=f"{acc.id}:export")],
        [InlineKeyboardButton(text=f"🌐 Прокси: {proxy_label}", callback_data=f"{acc.id}:edit_proxy")],
        [InlineKeyboardButton(text="🗑 Удалить", callback_data=f"{acc.id}:delete")],
        [InlineKeyboardButton(text="⬅️ К списку", callback_data="accounts_list")],
    ])

def get_settings_kb(acc: Account):
    zone_label = ', '.join(acc.active_regions)
    sleep_label = f"{acc.current_sleep_time // 60} мин" if acc.current_sleep_time >= 60 else f"{acc.current_sleep_time} сек"
    exhaust_label = f"{acc.pool_exhaust_threshold}%" if acc.pool_exhaust_threshold > 0 else "ВЫКЛ"
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=f"📍 Зоны: {zone_label}", callback_data=f"{acc.id}:cfg_zones")],
        [InlineKeyboardButton(text=f"⏳ Пауза: {sleep_label}", callback_data=f"{acc.id}:cfg_sleep")],
        [InlineKeyboardButton(text=f"📦 Батч: {acc.current_batch_size}", callback_data=f"{acc.id}:cfg_batch")],
        [InlineKeyboardButton(text=f"💳 Порог: {acc.balance_threshold:.0f} ₽", callback_data=f"{acc.id}:cfg_threshold")],
        [InlineKeyboardButton(text=f"🧠 Умные зоны: {'ВКЛ' if acc.smart_zone_mode else 'ВЫКЛ'}", callback_data=f"{acc.id}:toggle_smart")],
        [InlineKeyboardButton(text=f"🚫 Авто-пауза: {exhaust_label}", callback_data=f"{acc.id}:cfg_exhaust")],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data=f"{acc.id}:panel")],
    ])

def get_zones_kb(acc: Account):
    kb = []
    for reg in ALL_REGIONS:
        mark = " ✓" if reg in acc.active_regions else ""
        kb.append([InlineKeyboardButton(text=f"{reg}{mark}", callback_data=f"{acc.id}:zt_{reg}")])
    kb.append([InlineKeyboardButton(text="✅ Все зоны", callback_data=f"{acc.id}:zone_all")])
    kb.append([InlineKeyboardButton(text="⬅️ Назад", callback_data=f"{acc.id}:settings")])
    return InlineKeyboardMarkup(inline_keyboard=kb)

def get_sleep_kb(acc: Account):
    options = [60, 180, 300, 600]
    buttons = [InlineKeyboardButton(
        text=f"{s // 60} мин{' ✓' if s == acc.current_sleep_time else ''}",
        callback_data=f"{acc.id}:sl_{s}") for s in options]
    return InlineKeyboardMarkup(inline_keyboard=[buttons, [InlineKeyboardButton(text="⬅️ Назад", callback_data=f"{acc.id}:settings")]])

def get_batch_kb(acc: Account):
    options = [1, 2, 3, 5]
    buttons = [InlineKeyboardButton(
        text=f"{n}{' ✓' if n == acc.current_batch_size else ''}",
        callback_data=f"{acc.id}:bt_{n}") for n in options]
    return InlineKeyboardMarkup(inline_keyboard=[buttons, [InlineKeyboardButton(text="⬅️ Назад", callback_data=f"{acc.id}:settings")]])

def get_threshold_kb(acc: Account):
    options = [0, 3, 5, 10, 20]
    buttons = [InlineKeyboardButton(
        text=f"{'ВЫКЛ' if v == 0 else f'{v} ₽'}{' ✓' if v == acc.balance_threshold else ''}",
        callback_data=f"{acc.id}:th_{v}") for v in options]
    return InlineKeyboardMarkup(inline_keyboard=[buttons, [InlineKeyboardButton(text="⬅️ Назад", callback_data=f"{acc.id}:settings")]])

def get_exhaust_kb(acc: Account):
    options = [0, 70, 80, 85, 90]
    buttons = [InlineKeyboardButton(
        text=f"{'ВЫКЛ' if v == 0 else f'{v}%'}{' ✓' if v == acc.pool_exhaust_threshold else ''}",
        callback_data=f"{acc.id}:ex_{v}") for v in options]
    return InlineKeyboardMarkup(inline_keyboard=[buttons, [InlineKeyboardButton(text="⬅️ Назад", callback_data=f"{acc.id}:settings")]])


# ============================================================
#  ХЭНДЛЕРЫ — глобальные (зарегистрированы ПЕРВЫМИ по приоритету)
# ============================================================

@dp.message(Command("start"))
async def cmd_start(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID: return
    await state.clear()
    await message.answer("🤖 <b>Selectel IP Sniper</b>\n\nВыберите действие:", parse_mode="HTML", reply_markup=get_main_kb())

@dp.message(F.text == "👥 Аккаунты")
async def btn_accounts(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID: return
    await state.clear()
    accs = manager.list_all()
    text = f"👥 <b>Аккаунты ({len(accs)}):</b>" if accs else "📭 <b>Нет аккаунтов.</b>\n\nДобавьте первый:"
    await message.answer(text, parse_mode="HTML", reply_markup=get_accounts_kb())

@dp.message(F.text == "📋 Подсети")
async def btn_subnets(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID: return
    await state.clear()
    lines = [f"<code>{net}</code>" for net in networks]
    text = f"📋 <b>Белый список ({len(networks)} шт.):</b>\n\n" + "\n".join(lines)
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔄 Перезагрузить whitelist", callback_data="reload_whitelist")]
    ])
    await message.answer(text, parse_mode="HTML", reply_markup=kb)

# --- Глобальные коллбэки ---
@dp.callback_query(F.data == "accounts_list")
async def cb_accounts_list(call: CallbackQuery, state: FSMContext):
    if call.from_user.id != ADMIN_ID: return
    await state.clear()
    accs = manager.list_all()
    text = f"👥 <b>Аккаунты ({len(accs)}):</b>" if accs else "📭 <b>Нет аккаунтов.</b>"
    await call.message.edit_text(text, parse_mode="HTML", reply_markup=get_accounts_kb())
    await call.answer()

@dp.callback_query(F.data == "reload_whitelist")
async def cb_reload_whitelist(call: CallbackQuery):
    if call.from_user.id != ADMIN_ID: return
    global networks, whitelist_total_ips, network_labels
    old_count = len(networks)
    try:
        networks, whitelist_total_ips, network_labels = load_whitelist()
        diff = len(networks) - old_count
        diff_str = f"+{diff}" if diff > 0 else str(diff) if diff < 0 else "±0"
        for acc in manager.list_all():
            acc.closest_miss = None
        await call.message.edit_text(
            f"✅ <b>Whitelist обновлён!</b>\n📋 {len(networks)} подсетей ({diff_str})\n🌐 {whitelist_total_ips} IP",
            parse_mode="HTML")
    except Exception as e:
        await call.message.edit_text(f"❌ <b>Ошибка:</b>\n<code>{e}</code>", parse_mode="HTML")
    await call.answer()


# ============================================================
#  FSM — добавление аккаунта
# ============================================================

@dp.callback_query(F.data == "add_account")
async def fsm_add_start(call: CallbackQuery, state: FSMContext):
    if call.from_user.id != ADMIN_ID: return
    await state.set_state(AddAccountFSM.waiting_name)
    await call.message.edit_text("➕ <b>Новый аккаунт</b>\n\nВведите название:", parse_mode="HTML")
    await call.answer()

@dp.message(AddAccountFSM.waiting_name)
async def fsm_add_name(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID: return
    name = message.text.strip()
    if not name or len(name) > 50:
        return await message.answer("❌ Название: 1–50 символов.")
    await state.update_data(name=name)
    await state.set_state(AddAccountFSM.waiting_token)
    await message.answer(f"📝 Название: <b>{name}</b>\n\nВведите <b>SELECTEL_TOKEN</b>:", parse_mode="HTML")

@dp.message(AddAccountFSM.waiting_token)
async def fsm_add_token(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID: return
    token = message.text.strip()
    if not token:
        return await message.answer("❌ Токен не может быть пустым.")
    await state.update_data(token=token)
    await state.set_state(AddAccountFSM.waiting_project_id)
    try:
        await message.delete()
    except Exception:
        pass
    await message.answer("✅ Токен получен.\n\nВведите <b>PROJECT_ID</b>:", parse_mode="HTML")

@dp.message(AddAccountFSM.waiting_project_id)
async def fsm_add_project(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID: return
    pid = message.text.strip()
    if not pid:
        return await message.answer("❌ PROJECT_ID не может быть пустым.")
    await state.update_data(project_id=pid)
    await state.set_state(AddAccountFSM.waiting_proxy)
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⏭ Пропустить (без прокси)", callback_data="add_skip_proxy")]
    ])
    await message.answer(
        "🌐 Введите <b>SOCKS5-прокси</b>\n<code>socks5://user:pass@host:port</code>\n\nИли пропустите:",
        parse_mode="HTML", reply_markup=kb)

@dp.callback_query(F.data == "add_skip_proxy")
async def fsm_add_skip_proxy(call: CallbackQuery, state: FSMContext):
    if call.from_user.id != ADMIN_ID: return
    if await state.get_state() != AddAccountFSM.waiting_proxy.state:
        return await call.answer()
    data = await state.get_data()
    await state.clear()
    acc = manager.add(data["name"], data["token"], data["project_id"])
    manager.save()
    manager.ensure_roller(acc)
    await call.message.edit_text(
        f"✅ <b>Аккаунт создан!</b>\n\n📝 {acc.name}\n🆔 {acc.id}\n🌐 Прокси: нет",
        parse_mode="HTML", reply_markup=get_account_panel_kb(acc))
    await call.answer()

@dp.message(AddAccountFSM.waiting_proxy)
async def fsm_add_proxy(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID: return
    proxy = message.text.strip()
    if not proxy.startswith("socks5://"):
        return await message.answer("❌ Формат: socks5://user:pass@host:port")
    data = await state.get_data()
    await state.clear()
    acc = manager.add(data["name"], data["token"], data["project_id"], proxy=proxy)
    manager.save()
    manager.ensure_roller(acc)
    try:
        await message.delete()
    except Exception:
        pass
    await message.answer(
        f"✅ <b>Аккаунт создан!</b>\n\n📝 {acc.name}\n🆔 {acc.id}\n🌐 Прокси: настроен",
        parse_mode="HTML", reply_markup=get_account_panel_kb(acc))


# ============================================================
#  FSM — редактирование прокси
# ============================================================

@dp.callback_query(F.data == "edit_proxy_remove")
async def fsm_proxy_remove(call: CallbackQuery, state: FSMContext):
    if call.from_user.id != ADMIN_ID: return
    if await state.get_state() != EditProxyFSM.waiting_proxy.state:
        return await call.answer()
    data = await state.get_data()
    acc = manager.get(data.get("account_id", ""))
    await state.clear()
    if not acc:
        return await call.answer("Аккаунт не найден", show_alert=True)
    acc.proxy = None
    await acc.close_session()
    manager.save()
    await call.message.edit_text(f"✅ Прокси убран для <b>{acc.name}</b>", parse_mode="HTML", reply_markup=get_account_panel_kb(acc))
    await call.answer()

@dp.message(EditProxyFSM.waiting_proxy)
async def fsm_proxy_input(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID: return
    proxy = message.text.strip()
    if not proxy.startswith("socks5://"):
        return await message.answer("❌ Формат: socks5://user:pass@host:port")
    data = await state.get_data()
    acc = manager.get(data.get("account_id", ""))
    await state.clear()
    if not acc:
        return await message.answer("❌ Аккаунт не найден.")
    acc.proxy = proxy
    await acc.close_session()
    manager.save()
    try:
        await message.delete()
    except Exception:
        pass
    await message.answer(f"✅ Прокси обновлён для <b>{acc.name}</b>", parse_mode="HTML", reply_markup=get_account_panel_kb(acc))


# ============================================================
#  РОУТЕР — коллбэки привязанные к аккаунту ({id}:{action})
# ============================================================

async def _send_account_status(call: CallbackQuery, acc: Account):
    """Сформировать и отправить дашборд аккаунта."""
    mode = "🟢 Активен" if acc.is_running else "🟡 На паузе"
    balance_text = await acc.get_balance()

    msg = f"🎛 <b>ДАШБОРД: {acc.name}</b>\n\n"
    msg += f"📡 {mode} · 📍 {', '.join(acc.active_regions)}\n"
    msg += f"\n{'━' * 20}\n"
    msg += f"📦 <b>Проверено:</b> {acc.stats['checked']} IP (уник: {len(acc.seen_ips)})\n"
    msg += f"🎯 <b>Найдено:</b> {acc.stats['found']} IP\n"
    if acc.found_ips:
        for fi in acc.found_ips:
            t = time.strftime('%d.%m %H:%M', time.localtime(fi['time']))
            label_tag = f" · {fi['label']}" if fi.get("label") else ""
            msg += f"  - <code>{fi['ip']}</code> ({fi['region']}, {t}){label_tag}\n"
    msg += f"💳 <b>Баланс:</b> {balance_text} ₽\n"
    msg += f"📋 <b>Whitelist:</b> {whitelist_total_ips} IP в {len(networks)} подсетях"

    est = acc.estimate_remaining()
    if est:
        rem_checks, rem_hours, cpc = est
        t = f"{rem_hours / 24:.1f} дн." if rem_hours >= 24 else f"{rem_hours:.1f} ч."
        msg += f"\n\n{'━' * 20}\n"
        msg += f"🔮 <b>Прогноз:</b> ~{rem_checks} прокрутов (~{t})\n"
        msg += f"💸 <b>Стоимость:</b> {cpc:.4f} ₽/прокрут"

    if acc.zone_stats:
        msg += f"\n\n{'━' * 20}\n🎲 <b>Анализ пула</b>\n"
        for zn in sorted(acc.zone_stats):
            zs = acc.zone_stats[zn]
            z_total = zs["checked"]
            z_cidrs = len(zs.get("seen_cidrs", {}))
            z_pool = estimate_pool_size(z_total, z_cidrs)
            if z_pool:
                msg += f"\n📍 <b>{zn}</b>\n   проверок: {z_total} · /24: {z_cidrs}\n   пул: ~{z_pool} · покрыто: {min(z_cidrs / z_pool * 100, 100):.0f}%"
            else:
                msg += f"\n📍 <b>{zn}</b> — {z_total} проверок, /24: {z_cidrs} (мало данных)"

    if acc.closest_miss:
        msg += f"\n\n{'━' * 20}\n🎯 <b>Ближайший промах</b>\n"
        msg += f"<code>{acc.closest_miss[0]}</code> → {acc.closest_miss[1]}\nРасстояние: {format_distance(acc.closest_miss[2])} IP"

    if len(msg) > 4000:
        msg = msg[:4000] + "\n\n<i>… (обрезано)</i>"

    try:
        await call.message.edit_text(msg, parse_mode="HTML", reply_markup=get_account_panel_kb(acc))
    except Exception:
        await bot.send_message(ADMIN_ID, msg, parse_mode="HTML", reply_markup=get_account_panel_kb(acc))

    # Файл с подсетями
    if acc.stats["subnet_counts"]:
        sorted_subnets = sorted(acc.stats["subnet_counts"].items(), key=lambda x: (x[1], -acc.stats["subnet_times"].get(x[0], 0)))
        lines = []
        if acc.zone_stats:
            lines.append("Статистика по зонам:\n" + "-" * 40 + "\n")
            for zn in sorted(acc.zone_stats):
                zs = acc.zone_stats[zn]
                z_total = zs["checked"]
                z_cidrs = len(zs.get("seen_cidrs", {}))
                z_rp = round((1 - z_cidrs / z_total) * 100) if z_total else 0
                lines.append(f"{zn}: {z_total} проверок, {z_cidrs} уник. /24, повторов {z_rp}%\n")
            lines.append("\n")
        lines.append("Подсети (от редких к частым):\n" + "-" * 40 + "\n")
        for sub, count in sorted_subnets:
            lines.append(f"{sub}: {count} шт.\n")
        doc = BufferedInputFile("".join(lines).encode("utf-8"), filename=f"subnets_{acc.name}.txt")
        await bot.send_document(chat_id=ADMIN_ID, document=doc, caption=f"📁 <b>Отчёт: {acc.name}</b>", parse_mode="HTML")


async def _send_account_export(call: CallbackQuery, acc: Account):
    """Экспорт IP-адресов аккаунта в файл."""
    if not acc.seen_ips:
        return

    zone_ips = {}
    for zn, zs in acc.zone_stats.items():
        zone_ips[zn] = sorted(zs["seen_ips"].keys(), key=lambda ip: tuple(map(int, ip.split('.'))))
    all_zone_set = {ip for ips in zone_ips.values() for ip in ips}
    orphan = sorted(set(acc.seen_ips.keys()) - all_zone_set, key=lambda ip: tuple(map(int, ip.split('.'))))

    lines = [f"Экспорт IP — {acc.name} — {time.strftime('%Y-%m-%d %H:%M:%S')}\n"]
    lines.append(f"Проверено: {acc.stats['checked']}, уникальных: {len(acc.seen_ips)}\n\n")
    for zn in sorted(zone_ips):
        ips = zone_ips[zn]
        lines.append(f"{'=' * 40}\n{zn} — {len(ips)} уник. IP\n{'=' * 40}\n")
        for ip in ips:
            cnt = acc.seen_ips.get(ip, 1)
            lines.append(f"{ip}" + (f"  (×{cnt})" if cnt > 1 else "") + "\n")
        lines.append("\n")
    if orphan:
        lines.append(f"{'=' * 40}\nБез зоны — {len(orphan)} IP\n{'=' * 40}\n")
        for ip in orphan:
            cnt = acc.seen_ips.get(ip, 1)
            lines.append(f"{ip}" + (f"  (×{cnt})" if cnt > 1 else "") + "\n")

    doc = BufferedInputFile("".join(lines).encode("utf-8"), filename=f"export_{acc.name}.txt")
    await bot.send_document(chat_id=ADMIN_ID, document=doc,
        caption=f"📥 <b>{acc.name}:</b> {len(acc.seen_ips)} уник. IP", parse_mode="HTML")


@dp.callback_query(lambda c: ":" in (c.data or ""))
async def account_router(call: CallbackQuery, state: FSMContext):
    if call.from_user.id != ADMIN_ID: return
    await state.clear()

    parts = call.data.split(":", 1)
    if len(parts) != 2:
        return await call.answer()
    acc_id, action = parts
    acc = manager.get(acc_id)
    if not acc:
        return await call.answer("Аккаунт не найден", show_alert=True)

    # --- Панель аккаунта ---
    if action == "panel":
        proxy_label = "настроен" if acc.proxy else "нет"
        await call.message.edit_text(
            f"{'🟢' if acc.is_running else '🟡'} <b>{acc.name}</b>\n"
            f"📦 Проверено: {acc.stats['checked']} · 🎯 Найдено: {acc.stats['found']}\n"
            f"🌐 Прокси: {proxy_label}",
            parse_mode="HTML", reply_markup=get_account_panel_kb(acc))

    elif action == "start":
        if acc.is_running:
            return await call.answer("Уже запущено!", show_alert=True)
        await manager.start_account(acc)
        await call.message.edit_text(
            f"🚀 <b>{acc.name}: Поиск запущен!</b>\n📍 Зоны: {', '.join(acc.active_regions)}",
            parse_mode="HTML", reply_markup=get_account_panel_kb(acc))

    elif action == "stop":
        if not acc.is_running:
            return await call.answer("Уже на паузе!", show_alert=True)
        await manager.stop_account(acc)
        deleted = await acc.cleanup_ips()
        await call.message.edit_text(
            f"⏸ <b>{acc.name}: Остановлен</b>\n🧹 Удалено: {deleted}",
            parse_mode="HTML", reply_markup=get_account_panel_kb(acc))

    elif action == "status":
        await _send_account_status(call, acc)

    elif action == "settings":
        await call.message.edit_text(f"⚙️ <b>Настройки: {acc.name}</b>", parse_mode="HTML", reply_markup=get_settings_kb(acc))

    elif action == "export":
        if not acc.seen_ips:
            return await call.answer("📭 Нет данных для экспорта.", show_alert=True)
        await _send_account_export(call, acc)

    elif action == "edit_proxy":
        await state.set_state(EditProxyFSM.waiting_proxy)
        await state.update_data(account_id=acc.id)
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🚫 Убрать прокси", callback_data="edit_proxy_remove")],
            [InlineKeyboardButton(text="⬅️ Отмена", callback_data=f"{acc.id}:panel")],
        ])
        cur = acc.proxy or "не задан"
        await call.message.edit_text(
            f"🌐 <b>Прокси: {acc.name}</b>\n\nТекущий: <code>{cur}</code>\n\n"
            f"Введите новый (socks5://user:pass@host:port):", parse_mode="HTML", reply_markup=kb)

    elif action == "delete":
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="❌ Да, удалить", callback_data=f"{acc.id}:delete_yes")],
            [InlineKeyboardButton(text="⬅️ Отмена", callback_data=f"{acc.id}:panel")],
        ])
        await call.message.edit_text(
            f"🗑 <b>Удалить {acc.name}?</b>\n\n"
            f"📦 Проверено: {acc.stats['checked']}\n🎯 Найдено: {acc.stats['found']}\n\n"
            f"<i>Действие необратимо!</i>", parse_mode="HTML", reply_markup=kb)

    elif action == "delete_yes":
        name = acc.name
        if acc.is_running:
            acc.is_running = False
            try:
                await acc.cleanup_ips()
            except Exception:
                pass
        if acc.roller_task and not acc.roller_task.done():
            acc.roller_task.cancel()
            try:
                await acc.roller_task
            except (asyncio.CancelledError, Exception):
                pass
        await acc.close_session()
        manager.remove(acc.id)
        manager.save()
        await call.message.edit_text(f"✅ Аккаунт <b>{name}</b> удалён.", parse_mode="HTML", reply_markup=get_accounts_kb())

    # --- Настройки: зоны ---
    elif action == "cfg_zones":
        await call.message.edit_text(f"📍 <b>Зоны: {acc.name}</b>", parse_mode="HTML", reply_markup=get_zones_kb(acc))

    elif action.startswith("zt_"):
        reg = action[3:]
        if reg in acc.active_regions:
            if len(acc.active_regions) > 1:
                acc.active_regions.remove(reg)
                acc.exhaust_pardoned.discard(reg)
            else:
                return await call.answer("Нужна хотя бы одна зона!", show_alert=True)
        else:
            acc.active_regions.append(reg)
            acc.exhaust_pardoned.add(reg)
        manager.save()
        await call.message.edit_text(
            f"📍 <b>Зоны ({len(acc.active_regions)}):</b> {', '.join(acc.active_regions)}",
            parse_mode="HTML", reply_markup=get_zones_kb(acc))

    elif action == "zone_all":
        acc.active_regions = list(ALL_REGIONS)
        acc.exhaust_pardoned.update(ALL_REGIONS)
        manager.save()
        await call.message.edit_text(
            f"📍 <b>Все зоны ({len(acc.active_regions)}):</b> {', '.join(acc.active_regions)}",
            parse_mode="HTML", reply_markup=get_zones_kb(acc))

    # --- Настройки: пауза ---
    elif action == "cfg_sleep":
        await call.message.edit_text(f"⏳ <b>Пауза: {acc.name}</b>", parse_mode="HTML", reply_markup=get_sleep_kb(acc))

    elif action.startswith("sl_"):
        acc.current_sleep_time = int(action[3:])
        manager.save()
        label = f"{acc.current_sleep_time // 60} мин" if acc.current_sleep_time >= 60 else f"{acc.current_sleep_time} сек"
        await call.message.edit_text(f"✅ Пауза: <b>{label}</b>", parse_mode="HTML", reply_markup=get_settings_kb(acc))

    # --- Настройки: батч ---
    elif action == "cfg_batch":
        await call.message.edit_text(f"📦 <b>Батч: {acc.name}</b>", parse_mode="HTML", reply_markup=get_batch_kb(acc))

    elif action.startswith("bt_"):
        acc.current_batch_size = int(action[3:])
        manager.save()
        await call.message.edit_text(f"✅ Батч: <b>{acc.current_batch_size}</b>", parse_mode="HTML", reply_markup=get_settings_kb(acc))

    # --- Настройки: порог баланса ---
    elif action == "cfg_threshold":
        await call.message.edit_text(f"💳 <b>Порог баланса: {acc.name}</b>", parse_mode="HTML", reply_markup=get_threshold_kb(acc))

    elif action.startswith("th_"):
        acc.balance_threshold = float(action[3:])
        manager.save()
        label = "ВЫКЛ" if acc.balance_threshold == 0 else f"{acc.balance_threshold:.0f} ₽"
        await call.message.edit_text(f"✅ Порог: <b>{label}</b>", parse_mode="HTML", reply_markup=get_settings_kb(acc))

    # --- Настройки: умные зоны ---
    elif action == "toggle_smart":
        acc.smart_zone_mode = not acc.smart_zone_mode
        manager.save()
        st = "ВКЛ" if acc.smart_zone_mode else "ВЫКЛ"
        desc = "Приоритет зоне с бóльшим пулом" if acc.smart_zone_mode else "Случайный выбор"
        await call.message.edit_text(f"🧠 Умные зоны: <b>{st}</b>\n<i>{desc}</i>", parse_mode="HTML", reply_markup=get_settings_kb(acc))

    # --- Настройки: авто-пауза зон ---
    elif action == "cfg_exhaust":
        await call.message.edit_text(f"🚫 <b>Авто-пауза зон: {acc.name}</b>", parse_mode="HTML", reply_markup=get_exhaust_kb(acc))

    elif action.startswith("ex_"):
        acc.pool_exhaust_threshold = int(action[3:])
        manager.save()
        label = "ВЫКЛ" if acc.pool_exhaust_threshold == 0 else f"{acc.pool_exhaust_threshold}%"
        await call.message.edit_text(f"✅ Авто-пауза: <b>{label}</b>", parse_mode="HTML", reply_markup=get_settings_kb(acc))

    await call.answer()


# ============================================================
#  ЖИЗНЕННЫЙ ЦИКЛ
# ============================================================
shutdown_event = asyncio.Event()

async def shutdown():
    summary_parts = []
    for acc in manager.list_all():
        was_running = acc.is_running
        acc.is_running = False
        deleted = 0
        if was_running:
            try:
                deleted = await acc.cleanup_ips()
            except Exception:
                pass
        summary_parts.append(
            f"  {'🟢' if was_running else '🟡'} {acc.name}: {acc.stats['checked']} проверок, {acc.stats['found']} найдено"
            + (f", очищено {deleted}" if deleted else ""))
        if acc.roller_task and not acc.roller_task.done():
            acc.roller_task.cancel()
            try:
                await acc.roller_task
            except (asyncio.CancelledError, Exception):
                pass
        await acc.close_session()
    manager.save()

    summary = "🛑 <b>Скрипт остановлен.</b>\n\n"
    summary += "\n".join(summary_parts) if summary_parts else "Нет аккаунтов."
    try:
        await bot.send_message(ADMIN_ID, summary, parse_mode="HTML")
    except Exception as e:
        logging.error(f"Ошибка отправки итога: {e}")

async def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', stream=sys.stdout)

    manager.load()

    # Очистка мусорных IP при старте
    startup = ["🤖 <b>Бот перезапущен!</b>"]
    for acc in manager.list_all():
        deleted = await acc.cleanup_ips()
        line = f"\n📂 <b>{acc.name}:</b> {acc.stats['checked']} проверок"
        if deleted:
            line += f", очищено {deleted} IP"
        startup.append(line)

    if not manager.list_all():
        startup.append("\n📭 Нет аккаунтов. Добавьте через меню 👥")

    await bot.send_message(ADMIN_ID, "".join(startup), parse_mode="HTML", reply_markup=get_main_kb())

    # Запуск roller-задач (все на паузе, пока админ не нажмёт «Запустить»)
    for acc in manager.list_all():
        manager.ensure_roller(acc)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown_event.set)
        except NotImplementedError:
            pass

    polling_task = asyncio.create_task(dp.start_polling(bot))

    try:
        await shutdown_event.wait()
    except asyncio.CancelledError:
        pass

    logging.info("Получен сигнал завершения...")
    await dp.stop_polling()
    polling_task.cancel()
    try:
        await polling_task
    except (asyncio.CancelledError, Exception):
        pass
    await shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
