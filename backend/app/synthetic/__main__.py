"""Command line for the synthetic dataset.

    python -m app.synthetic csv     --out ../outputs/fixit_synthetic_tickets.csv
    python -m app.synthetic import  [--replace] [--csv PATH]       # local databases only
    python -m app.synthetic status
    python -m app.synthetic purge   --yes                           # removes only SYN- tickets
    python -m app.synthetic import-remote --target-url URL --confirm-host HOST   # explicit, separate

The target database is DATABASE_URL (or --database-url). Remote hosts such as Supabase are
always refused by ``import``/``purge``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.synthetic", description="Datos sintéticos de FixIT (solo entorno local)")
    sub = parser.add_subparsers(dest="command", required=True)

    def gen_args(p):
        p.add_argument("--count", type=int, default=5000, help="Número de tickets (por defecto 5000)")
        p.add_argument("--seed", type=int, default=42, help="Semilla para reproducibilidad")
        p.add_argument("--end-date", type=date.fromisoformat, default=None, help="Último día simulado (AAAA-MM-DD). Por defecto: ayer")
        p.add_argument("--days", type=int, default=540, help="Días de historia simulada")

    p_csv = sub.add_parser("csv", help="Genera el dataset y lo exporta a CSV (no toca la base de datos)")
    gen_args(p_csv)
    p_csv.add_argument("--out", default="../outputs/fixit_synthetic_tickets.csv")

    p_imp = sub.add_parser("import", help="Genera e importa en la base LOCAL")
    gen_args(p_imp)
    p_imp.add_argument("--database-url", default=None, help="Por defecto DATABASE_URL")
    p_imp.add_argument("--replace", action="store_true", help="Elimina antes los tickets SYN- existentes")
    p_imp.add_argument("--csv", default=None, help="Además exporta el CSV a esta ruta")

    p_remote = sub.add_parser("import-remote", help="Destino adicional explícito (NO recomendado)")
    gen_args(p_remote)
    p_remote.add_argument("--target-url", required=True)
    p_remote.add_argument("--confirm-host", required=True, help="Escriba de nuevo el host exacto del destino")
    p_remote.add_argument("--replace", action="store_true")

    p_status = sub.add_parser("status", help="Cuenta tickets reales y sintéticos")
    p_status.add_argument("--database-url", default=None)

    p_purge = sub.add_parser("purge", help="Elimina solo los datos sintéticos de la base LOCAL")
    p_purge.add_argument("--database-url", default=None)
    p_purge.add_argument("--yes", action="store_true", help="Confirma la eliminación de registros SYN-")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    explicit_url = getattr(args, "database_url", None) or getattr(args, "target_url", None)
    if explicit_url and not os.getenv("DATABASE_URL"):
        os.environ["DATABASE_URL"] = explicit_url
    # The CLI never issues tokens; a placeholder only satisfies the shared settings object.
    os.environ.setdefault("JWT_SECRET_KEY", "synthetic-cli-placeholder-not-used-for-tokens")

    from app.synthetic.generator import generate, write_csv

    if args.command == "csv":
        ds = generate(args.count, args.seed, args.end_date, args.days)
        rows = write_csv(ds, args.out)
        print(json.dumps({"csv": os.path.abspath(args.out), "rows": rows, "summary": ds.summary()}, ensure_ascii=False, indent=2))
        return 0

    from sqlalchemy import create_engine
    from app.core.config import settings
    from app.synthetic import importer

    url = explicit_url or settings.database_url
    try:
        if args.command == "import-remote":
            info = importer.assert_remote_confirmed(url, args.confirm_host)
        else:
            info = importer.assert_local(url)
    except importer.UnsafeTargetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Destino: {info['backend']} @ {info['host']} ({'local' if info['local'] else 'REMOTO'})", file=sys.stderr)
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)

    if args.command == "status":
        print(json.dumps(importer.status(engine), ensure_ascii=False, indent=2, default=str))
        return 0
    if args.command == "purge":
        if not args.yes:
            print("Añada --yes para confirmar. Solo se eliminan tickets SYN- y usuarios @sintetico.fixit.example sin actividad real.", file=sys.stderr)
            return 1
        print(json.dumps(importer.purge(engine), ensure_ascii=False, indent=2))
        return 0

    ds = generate(args.count, args.seed, args.end_date, args.days)
    try:
        result = importer.import_dataset(engine, ds, replace=args.replace)
    except importer.SyntheticDataExists as exc:
        print(f"AVISO: {exc}", file=sys.stderr)
        return 3
    if getattr(args, "csv", None):
        write_csv(ds, args.csv)
        result["csv"] = os.path.abspath(args.csv)
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    print("Usuarios de demostración: <nombre>@sintetico.fixit.example, contraseña FIXIT_SYNTHETIC_PASSWORD (por defecto Demo!2026).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
