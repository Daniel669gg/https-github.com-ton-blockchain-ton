# Ghost Security — VS Code Extension

Inline AppSec scanner powered by Ghost Security Platform.

## Features

- **Scan on save** — автоматически сканирует файл при сохранении
- **Inline diagnostics** — красные/жёлтые подчёркивания прямо в коде
- **Code Lens** — подсказки над уязвимыми строками
- **Quick Fix** — правой кнопкой → "Ghost: Explain" или "Ghost: AI Fix"
- **Findings Panel** — вся панель с находками в боковом баре
- **CWE/OWASP links** — клик на rule_id открывает документацию
- **Ollama AI** — объяснения и фиксы через локальный LLM (опционально)

## Установка

### Из VSIX (рекомендуется)
```bash
cd vscode_extension
npm install
npm run package        # создаёт ghost-security-1.0.0.vsix
code --install-extension ghost-security-1.0.0.vsix
```

### Разработка
```bash
npm install
npm run watch          # компиляция в watch mode
# F5 в VS Code → Extension Development Host
```

## Требования

Ghost Security server должен быть запущен:
```bash
cd ..
docker compose up      # или
python3 -m uvicorn api.server:app --port 8000
```

## Настройки

| Настройка | По умолчанию | Описание |
|---|---|---|
| `ghost.serverUrl` | `http://localhost:8000` | URL Ghost API |
| `ghost.scanOnSave` | `true` | Скан при сохранении |
| `ghost.scanOnType` | `false` | Скан при вводе (slow) |
| `ghost.minSeverity` | `MEDIUM` | Минимальный severity для показа |
| `ghost.showInlineHints` | `true` | Code Lens над уязвимыми строками |
| `ghost.autoFix` | `true` | AI-фиксы через Ollama |

## Поддерживаемые языки

Python · JavaScript · TypeScript · Solidity · JSX/TSX

## Команды

| Команда | Описание |
|---|---|
| `Ghost: Scan Current File` | Сканировать открытый файл |
| `Ghost: Scan Workspace` | Сканировать весь проект |
| `Ghost: Show Findings` | Открыть панель findings |
| `Ghost: Clear Diagnostics` | Очистить все подсветки |
| `Ghost: Explain This Finding` | AI-объяснение уязвимости |
| `Ghost: Generate Fix (AI)` | AI-фикс через Ollama |
