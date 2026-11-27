# yamreg

Сервер реестра пакетов для YAM.

## Запуск локально

Нужен Rust и OpenSSL.

```sh
cp .env.example .env
# Заполните значения в .env
cargo run -- serve
```

По умолчанию сервер доступен на `http://127.0.0.1:8080`.

## Публикация

1. Войдите через GitHub.
2. Создайте namespace и ключ автора.
3. Создайте publish-токен.
4. Используйте токен для загрузки пакетов.

Закрытый ключ автора храните отдельно и никому не передавайте.

## Docker

```sh
cp .env.production.example .env.production
# Заполните .env.production

docker compose up -d --build
```

Перед запуском настройте DNS для доменов из `Caddyfile` и откройте порт `443`.

## Команды

```sh
# Зарегистрировать namespace
cargo run -- add-namespace <namespace> <public-key>

# Отозвать версию
cargo run -- revoke <namespace>/<package> <version> --reason <причина>

# Пересобрать индексы
cargo run -- reindex --signing-key "$YAMREG_SIGNING_KEY"
```

Данные хранятся в `yamreg-data/`. Секреты и каталог данных не добавляются в Git.

ня!
/ᐠ - ˕ -マ Ⳋ
