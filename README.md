# AlfaMail

Bezpieczna platforma do wymiany wiadomości z szyfrowaniem end-to-end, obowiązkowym uwierzytelnianiem dwuskładnikowym (TOTP) i podpisami cyfrowymi RSA.

---

## Spis treści

- [Architektura](#architektura)
- [Funkcje bezpieczeństwa](#funkcje-bezpieczeństwa)
- [Wymagania](#wymagania)
- [Uruchomienie](#uruchomienie)
- [Konfiguracja](#konfiguracja)
- [Przepływ użytkownika](#przepływ-użytkownika)
- [Technologie](#technologie)
- [Struktura projektu](#struktura-projektu)

---

## Architektura

```
Przeglądarka
     │ HTTPS (443)
     ▼
  Nginx (proxy)
     │
     ├──► Frontend (pliki statyczne: HTML/JS)
     │
     └──► Backend (FastAPI, port 8000)
               │
               └──► SQLite (dane użytkowników i wiadomości)
```

Cały ruch HTTP jest automatycznie przekierowywany na HTTPS. Nginx pełni rolę reverse proxy – serwuje frontend jako pliki statyczne i przekazuje żądania do API backendu.

---

## Funkcje bezpieczeństwa

| Mechanizm | Implementacja |
|---|---|
| Hashowanie haseł | **Argon2id** |
| Uwierzytelnianie dwuskładnikowe | **TOTP** (RFC 6238), obowiązkowe dla wszystkich kont |
| Szyfrowanie wiadomości | Hybrydowe: **AES-256-GCM** (treść) + **RSA-2048-OAEP** (klucz) |
| Podpisy cyfrowe | **RSA-PSS** z SHA-256 |
| Tokeny sesji | **JWT** (HS256), dwufazowe (`pre_2fa_token` → `access_token`) |
| Ochrona przed brute-force | Progresywna blokada konta po 5 nieudanych próbach logowania |
| Ochrona 2FA | Blokada na 5 minut po 5 błędnych kodach TOTP |
| Transport | **TLS/HTTPS** |
| Nagłówki HTTP | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Logi audytowe | Rejestrowanie zdarzeń logowania w bazie danych |

### Jak działa szyfrowanie wiadomości?

1. Nadawca generuje jednorazowy klucz AES-256 i szyfruje nim treść wiadomości (AES-GCM).
2. Klucz AES jest szyfrowany kluczem publicznym RSA odbiorcy (OAEP/SHA-256).
3. Nadawca podpisuje treść swoim kluczem prywatnym (RSA-PSS).
4. Serwer przechowuje wyłącznie zaszyfrowane dane – nigdy nie ma dostępu do treści wiadomości.
5. Odbiorca odszyfrowuje klucz AES swoim kluczem prywatnym, a następnie odszyfrowuje treść i weryfikuje podpis.

---

## Wymagania

- [Docker](https://www.docker.com/) i [Docker Compose](https://docs.docker.com/compose/)
- Certyfikat TLS i klucz prywatny (`nginx.crt`, `nginx.key`) w głównym katalogu projektu

### Generowanie certyfikatu self-signed (tylko do celów deweloperskich)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx.key -out nginx.crt \
  -subj "/CN=localhost"
```

---

## Uruchomienie

1. **Sklonuj repozytorium** i przejdź do katalogu projektu.

2. **Ustaw zmienną środowiskową** `SECRET_KEY` (używana do podpisywania tokenów JWT):

   ```bash
   # Linux/macOS
   export SECRET_KEY=$(openssl rand -hex 64)

   # Windows (PowerShell)
   $env:SECRET_KEY = [System.Convert]::ToBase64String((1..64 | ForEach-Object { [byte](Get-Random -Max 256) }))
   ```

   Możesz też umieścić ją w pliku `.env` w katalogu projektu:

   ```env
   SECRET_KEY=twoj_bardzo_tajny_klucz
   ```

3. **Uruchom aplikację:**

   ```bash
   docker compose up --build
   ```

4. **Otwórz przeglądarkę** i przejdź pod adres `https://localhost`.

   > Przy certyfikacie self-signed przeglądarka wyświetli ostrzeżenie – możesz je zaakceptować w celach deweloperskich.

---

## Konfiguracja

| Zmienna środowiskowa | Opis | Domyślnie |
|---|---|---|
| `SECRET_KEY` | Klucz do podpisywania tokenów JWT | Losowy (niezalecane w produkcji) |
| `DATABASE_URL` | Adres bazy danych SQLAlchemy | `sqlite:///./data/alfa_mail.db` |

---

## Przepływ użytkownika

### Rejestracja i aktywacja 2FA

```
1. Rejestracja (POST /register)
       ↓
   Serwer zwraca sekret TOTP + URI do QR kodu
       ↓
2. Użytkownik skanuje QR kod w aplikacji (Google Authenticator, Aegis itp.)
       ↓
3. Aktywacja 2FA (POST /2fa/enable) – weryfikacja pierwszego kodu TOTP
       ↓
   Konto aktywowane
```

### Logowanie (dwufazowe)

```
1. POST /login (login + hasło)
       ↓
   Serwer zwraca `pre_2fa_token` (ważny 5 min)
       ↓
2. POST /login/verify-2fa (kod TOTP + pre_2fa_token)
       ↓
   Serwer zwraca `access_token` (ważny 30 min)
```

### Wysyłanie zaszyfrowanej wiadomości

```
1. Generowanie kluczy RSA (POST /keys/generate) – klucz publiczny trafia na serwer;
   klucz prywatny (zaszyfrowany hasłem użytkownika) jest przechowywany lokalnie lub w sejfie serwera.
       ↓
2. Wysłanie wiadomości (POST /messages/send):
   - Treść szyfrowana kluczem publicznym odbiorcy (AES-GCM + RSA-OAEP)
   - Treść podpisywana kluczem prywatnym nadawcy (RSA-PSS)
       ↓
3. Odczyt wiadomości (POST /messages/my):
   - Odszyfrowanie własnym kluczem prywatnym
   - Weryfikacja podpisu nadawcy
```

---

## Technologie

### Backend
- **Python 3.11+**
- **FastAPI** – framework REST API
- **SQLAlchemy** – ORM, baza danych SQLite
- **Argon2-cffi** – hashowanie haseł (Argon2id)
- **python-jose** – generowanie i weryfikacja tokenów JWT
- **pyotp** – implementacja TOTP (RFC 6238)
- **cryptography** – RSA, AES-GCM, podpisy cyfrowe

### Frontend
- Vanilla HTML / CSS / JavaScript (bez zewnętrznych frameworków)

### Infrastruktura
- **Docker Compose** – orkiestracja kontenerów
- **Nginx** – reverse proxy, TLS termination, serwowanie pliku statycznych

---

## Struktura projektu

```
AlfaMail/
├── backend/
│   ├── main.py          # Definicje endpointów FastAPI
│   ├── auth.py          # Hasła (Argon2), JWT, TOTP
│   ├── crypto_utils.py  # RSA, AES-GCM, podpisy
│   ├── models.py        # Modele SQLAlchemy (User, Message, AuditLog)
│   ├── schemas.py       # Schematy Pydantic (walidacja żądań/odpowiedzi)
│   ├── database.py      # Konfiguracja sesji bazy danych
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── index.html       # Strona logowania
│   ├── register.html    # Strona rejestracji + setup 2FA
│   ├── messages.html    # Skrzynka odbiorcza
│   └── app.js           # Logika klienta (szyfrowanie, API)
├── nginx/
│   ├── nginx.conf       # Konfiguracja Nginx (HTTPS, proxy, nagłówki CSP)
│   └── Dockerfile
├── nginx.crt            # Certyfikat TLS (nie commitować do repo!)
├── nginx.key            # Klucz prywatny TLS (nie commitować do repo!)
└── docker-compose.yml
```

> **Uwaga:** Pliki `nginx.crt` i `nginx.key` nie powinny być przechowywane w repozytorium Git – dodaj je do `.gitignore`.

---

## API – skrócona dokumentacja

Interaktywna dokumentacja Swagger UI dostępna pod adresem `https://localhost/docs` po uruchomieniu aplikacji.

| Metoda | Endpoint | Opis |
|---|---|---|
| `POST` | `/register` | Rejestracja nowego konta + inicjalizacja TOTP |
| `POST` | `/2fa/enable` | Aktywacja 2FA (weryfikacja pierwszego kodu) |
| `POST` | `/login` | Logowanie – faza 1 (zwraca `pre_2fa_token`) |
| `POST` | `/login/verify-2fa` | Logowanie – faza 2 (weryfikacja TOTP, zwraca `access_token`) |
| `POST` | `/keys/generate` | Generowanie lub odtworzenie pary kluczy RSA |
| `POST` | `/messages/send` | Wysłanie zaszyfrowanej wiadomości |
| `POST` | `/messages/my` | Pobranie i odszyfrowanie własnych wiadomości |
| `PATCH` | `/messages/{id}/read` | Oznaczenie wiadomości jako przeczytanej |
| `DELETE` | `/messages/{id}` | Usunięcie wiadomości |
