import json
import os
import re
from typing import Any, Dict, List, Tuple

import psycopg2
from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# Полный доступ к файлам на Google Диске текущего пользователя.
# Нужен, чтобы можно было создавать копии таблиц в вашем аккаунте.
SCOPES = ["https://www.googleapis.com/auth/drive"]


def load_config_from_env() -> Dict[str, Any]:
    """
    Загружает настройки из переменных окружения (.env / env.example).
    """
    load_dotenv()

    db_cfg = {
        "host": os.getenv("PG_HOST", "localhost"),
        "port": int(os.getenv("PG_PORT", "5432")),
        "dbname": os.getenv("PG_DBNAME", ""),
        "user": os.getenv("PG_USER", ""),
        "password": os.getenv("PG_PASSWORD", ""),
    }

    google_cfg = {
        "credentials_file": os.getenv("GOOGLE_CREDENTIALS_FILE", "credentials.json"),
        "token_file": os.getenv("GOOGLE_TOKEN_FILE", "token.json"),
        "destination_folder_id": os.getenv("GOOGLE_DESTINATION_FOLDER_ID") or None,
        # Альтернатива credentials.json: можно явно задать client_id и client_secret
        "client_id": os.getenv("GOOGLE_CLIENT_ID") or None,
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET") or None,
    }

    output_cfg = {
        "mapping_file": os.getenv("MAPPING_FILE", "mapping.json"),
    }

    return {
        "db": db_cfg,
        "google": google_cfg,
        "output": output_cfg,
    }


def get_credentials(
    credentials_file: str,
    token_file: str,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> Credentials:
    """
    Получает/обновляет OAuth2-учётные данные.

    credentials_file — JSON, скачанный из Google Cloud Console (OAuth Client ID, Desktop).
    token_file — локальный файл, куда библиотека сохранит access/refresh токены
                 после первого входа через браузер.
    """
    creds: Credentials | None = None

    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)

    # Если токен отсутствует или невалиден — запускаем браузер и авторизацию.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Токен просрочен, но есть refresh_token — просто обновляем.
            creds.refresh(Request())
        else:
            # Первый запуск: либо читаем client_id / client_secret из env,
            # либо используем credentials_file.
            if client_id and client_secret:
                client_config = {
                    "installed": {
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                    }
                }
                flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_file,
                    SCOPES,
                )

            creds = flow.run_local_server(port=0)

        with open(token_file, "w", encoding="utf-8") as token:
            token.write(creds.to_json())

    return creds


def extract_spreadsheet_id(url: str) -> str | None:
    """
    Извлекает spreadsheetId из URL Google Таблицы.

    Примеры URL:
    - https://docs.google.com/spreadsheets/d/<ID>/edit#gid=0
    - https://docs.google.com/spreadsheets/d/<ID>/
    """
    if not url:
        return None

    match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", url)
    if match:
        return match.group(1)
    return None


def fetch_clients(connection) -> List[Tuple[int, str]]:
    """
    Достаёт id и google_sheet_url всех клиентов.
    """
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT id, google_sheet_url
            FROM public.clients
            WHERE google_sheet_url IS NOT NULL
            """
        )
        rows = cur.fetchall()
    return rows


def copy_spreadsheet(
    drive_service,
    spreadsheet_id: str,
    destination_folder_id: str | None,
    client_id: int,
) -> str:
    """
    Копирует Google Таблицу и возвращает новую ссылку на копию.
    Имя новой таблицы — "<client_id> (copy)".
    """
    body: Dict[str, Any] = {"name": f"{client_id} (copy)"}

    if destination_folder_id:
        body["parents"] = [destination_folder_id]

    new_file = (
        drive_service.files()
        .copy(fileId=spreadsheet_id, body=body, fields="id")
        .execute()
    )

    new_file_id = new_file["id"]
    new_url = f"https://docs.google.com/spreadsheets/d/{new_file_id}/edit"
    return new_url


def main() -> None:
    config = load_config_from_env()
    db_cfg = config["db"]
    google_cfg = config["google"]
    output_cfg = config["output"]

    mapping_file = output_cfg["mapping_file"]

    # Подключаемся к базе данных
    conn = psycopg2.connect(
        host=db_cfg["host"],
        port=db_cfg["port"],
        dbname=db_cfg["dbname"],
        user=db_cfg["user"],
        password=db_cfg["password"],
    )

    try:
        clients = fetch_clients(conn)
        total_clients = len(clients)
        print(f"Найдено клиентов: {total_clients}")

        # Авторизация в Google Drive API
        creds = get_credentials(
            google_cfg["credentials_file"],
            google_cfg["token_file"],
            google_cfg.get("client_id"),
            google_cfg.get("client_secret"),
        )
        drive_service = build("drive", "v3", credentials=creds)

        # Для статистики считаем уникальные исходные spreadsheetId,
        # но копию делаем для каждого клиента отдельно (имя зависит от client_id).
        unique_source_sheet_ids: set[str] = set()
        results: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for client_id, url in clients:
            spreadsheet_id = extract_spreadsheet_id(url)

            if not spreadsheet_id:
                msg = "Не удалось извлечь spreadsheetId из URL"
                print(f"[WARN] client_id={client_id}: {msg} ({url})")
                errors.append(
                    {
                        "client_id": client_id,
                        "url": url,
                        "error": msg,
                    }
                )
                continue

            unique_source_sheet_ids.add(spreadsheet_id)

            try:
                new_url = copy_spreadsheet(
                    drive_service,
                    spreadsheet_id,
                    google_cfg["destination_folder_id"],
                    client_id,
                )
                print(f"[OK] client_id={client_id}: создана копия {new_url}")
            except HttpError as e:
                msg = f"Ошибка Google API: {e}"
                print(f"[ERROR] client_id={client_id}: {msg}")
                errors.append(
                    {
                        "client_id": client_id,
                        "url": url,
                        "spreadsheet_id": spreadsheet_id,
                        "error": str(e),
                    }
                )
                continue
            except Exception as e:
                msg = f"Неизвестная ошибка копирования: {e}"
                print(f"[ERROR] client_id={client_id}: {msg}")
                errors.append(
                    {
                        "client_id": client_id,
                        "url": url,
                        "spreadsheet_id": spreadsheet_id,
                        "error": str(e),
                    }
                )
                continue

            results.append(
                {
                    "client_id": client_id,
                    "old_url": url,
                    "new_url": new_url,
                }
            )

        # Сохраняем mapping.json
        output_data = {
            "clients": results,
            "errors": errors,
            "stats": {
                "total_clients": total_clients,
                "processed_clients": len(results),
                "unique_source_sheets": len(unique_source_sheet_ids),
                "errors_count": len(errors),
            },
        }

        with open(mapping_file, "w", encoding="utf-8") as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)

        print(f"\nГотово. Результат сохранён в {mapping_file}")
        print(f"Успешных клиентов: {len(results)}, ошибок: {len(errors)}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()


