# Server-Log-Mining

Local Dockerized analytics tool for Laravel and Nginx log ZIP files.

## Main idea

You do **not** need to upload both Nginx and Laravel logs. Any one ZIP is enough.

- If only `input/laravel/*.zip` exists, it analyzes Laravel logs.
- If only `input/nginx/*.zip` exists, it analyzes Nginx logs.
- If both exist, `auto` analyzes both.

## Folder structure

```text
Server-Log-Mining/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
├── app/
│   └── analyze.py
├── input/
│   ├── nginx/
│   │   └── put-nginx-zip-here.zip
│   └── laravel/
│       └── put-laravel-zip-here.zip
├── output/
└── work/
```

## Build

```bash
docker compose build
```

## Run auto mode

Recommended command:

```bash
docker compose run --rm log-analyzer
```

or explicitly:

```bash
docker compose run --rm log-analyzer python analyze.py auto
```

## Run only Laravel

Put ZIP here:

```text
input/laravel/laravel-logs.zip
```

Then:

```bash
docker compose run --rm log-analyzer python analyze.py laravel
```

## Run only Nginx

Put ZIP here:

```text
input/nginx/nginx-logs.zip
```

Then:

```bash
docker compose run --rm log-analyzer python analyze.py nginx
```

## Important correction

If you run this command:

```bash
docker compose run --rm log-analyzer python analyze.py nginx
```

but there is no ZIP in `input/nginx/`, the script will now check whether Laravel ZIP exists. If Laravel ZIP exists, it will automatically analyze Laravel instead of stopping.

## Output

Reports are generated in:

```text
output/nginx-report/
output/laravel-report/
```

Each report contains:

- `report.md`
- CSV summaries
- chart PNG files when enough data exists
