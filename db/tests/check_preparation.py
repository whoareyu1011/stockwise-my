"""Offline structural checks only. Does not connect to or execute SQL."""

from pathlib import Path
import json
import re


ROOT = Path(__file__).resolve().parents[2]
sql = (ROOT / "db/migrations/0001_inventory.sql").read_text()
clean = re.sub(r"--[^\n]*", "", sql)
expected = {
    "companies", "products", "contacts", "orders", "order_items",
    "stock_balances", "stock_movements", "audit_logs",
}
tables = re.findall(r"CREATE TABLE stockwise\.(\w+)\s*\(", clean)
assert len(tables) == 8 and set(tables) == expected, tables
assert set(re.findall(r"ALTER TABLE stockwise\.(\w+) ENABLE ROW LEVEL SECURITY", clean)) == expected
assert not re.search(r"\b(?:CREATE|ALTER|DROP)\s+ROLE\b", clean, re.I)
assert not re.search(r"\bGRANT\b", clean, re.I)
assert not re.search(r"\b(?:DROP|TRUNCATE)\s+(?:TABLE|SCHEMA)\b", clean, re.I)
assert clean.strip().startswith("BEGIN;") and clean.strip().endswith("COMMIT;")
for tag in re.findall(r"\$[A-Za-z_][A-Za-z_0-9]*\$", clean):
    assert clean.count(tag) % 2 == 0, f"Unbalanced dollar quote: {tag}"
functions = re.findall(
    r"CREATE FUNCTION stockwise\.(\w+)\s*\(.*?\)\s*RETURNS .*?AS \$fn\$(.*?)\$fn\$;",
    clean, re.S,
)
assert len(functions) >= 10, "Function scan incomplete"
headers = re.findall(r"CREATE FUNCTION stockwise\.\w+.*?AS \$fn\$", clean, re.S)
assert len(headers) == len(functions)
assert all("SET search_path = pg_catalog, pg_temp" in h for h in headers)
named_headers = dict(re.findall(
    r"CREATE FUNCTION stockwise\.(\w+)(.*?)AS \$fn\$", clean, re.S
))
expected_definers = {
    "initialize_balance", "audit_catalogue_change", "apply_movement",
    "check_balance_integrity", "check_order_integrity", "post_order", "reverse_order",
}
assert {
    name for name, header in named_headers.items() if "SECURITY DEFINER" in header
} == expected_definers
assert not any(re.search(r"\bEXECUTE\b", body) for _, body in functions), "No dynamic SQL in function bodies"
assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA stockwise FROM PUBLIC;" in clean
for name in [
    "stock_movements_one_original_item_uq", "stock_movements_one_reversal_uq",
    "stock_movements_one_opening_uq", "orders_one_full_reversal_uq",
    "stock_balances_consistency", "orders_consistency",
]:
    assert name in clean, name
assert "pg_catalog.pg_trigger_depth() <> 2" in clean
assert "quantity::numeric + NEW.quantity_delta::numeric >= 0" in clean
assert "IF v_balance IS NULL OR v_balance::numeric <> v_ledger" in clean
guard = dict(functions)["guard_order"]
assert "NEW.total" not in guard and "OLD.total" not in guard
assert "NEW.subtotal,NEW.discount_total" in guard
assert "NEW.original_order_id,NEW.posted_at,NEW.created_at" in guard
integrity = dict(functions)["check_order_integrity"]
assert "a.details->>'operation_key'=v_order.posting_key::text" in integrity
assert "A reversal has linked opposite movements, not ordinary order items" in integrity
assert "v_order.contact_id IS DISTINCT FROM v_original.contact_id" in integrity
reverse = dict(functions)["reverse_order"]
assert (
    reverse.index("INSERT INTO stockwise.orders")
    < reverse.index("INSERT INTO stockwise.stock_movements")
    < reverse.index("SET status='reversed'")
    < reverse.index("INSERT INTO stockwise.audit_logs")
)
assert "FORCE ROW LEVEL SECURITY" not in clean, "Owner trigger writes would need a revised policy design"
for target in ["products", "contacts", "orders", "order_items", "stock_movements"]:
    for columns in re.findall(rf"REFERENCES stockwise\.{target}\(([^)]+)\)", clean):
        assert columns.strip().startswith("company_id,"), (target, columns)
package = json.loads((ROOT / "package.json").read_text())
assert package["scripts"]["start"] == "node server.js"
assert not any("migration" in str(v).lower() for v in package["scripts"].values())
assert "0001_inventory" not in (ROOT / "server.js").read_text()
print(f"PASS: {len(tables)} tables, {len(functions)} function definitions, {len(expected_definers)} expected definers.")
print("PASS: closed grants, scoped references, reversal command order and audit-check structure.")
print("PASS: no role creation, runtime grant, destructive backout or startup migration hook.")
print("LIMIT: structural checks only; not a SQL/PLpgSQL parser and not a database/concurrency test.")
