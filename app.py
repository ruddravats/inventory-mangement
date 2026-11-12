from __future__ import annotations

import math
import os
import secrets
import sqlite3
import uuid
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path

import numpy as np
import pandas as pd
from flask import Flask, jsonify, request, send_from_directory
from sklearn.linear_model import LinearRegression
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).parent
DB_PATH = ROOT / "dataset_5yr" / "stocksphere_5yr.db"
app = Flask(__name__, static_folder="static")
sessions: dict[str, dict] = {}
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "480"))
MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))


def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")
    return connection


def rows(query, params=()):
    with db() as connection:
        return [dict(item) for item in connection.execute(query, params).fetchall()]


def one(query, params=()):
    result = rows(query, params)
    return result[0] if result else None


def log_inventory_tx(connection, user, product_id, transaction_type, before_qty, delta_qty,
                     reason="", source_warehouse_id=None, source_bin=None,
                     dest_warehouse_id=None, dest_bin=None, batch_id=None, serial_id=None,
                     request_id=None, order_id=None, po_id=None):
    connection.execute("""
        INSERT INTO inventory_transactions(
            transaction_id,timestamp,product_id,batch_id,serial_id,source_warehouse_id,source_bin,
            dest_warehouse_id,dest_bin,before_qty,delta_qty,after_qty,transaction_type,reason,
            user_id,operator,request_id,order_id,po_id
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        str(uuid.uuid4()), datetime.now().isoformat(), int(product_id), batch_id, serial_id,
        source_warehouse_id, source_bin, dest_warehouse_id, dest_bin,
        int(before_qty), int(delta_qty), int(before_qty)+int(delta_qty),
        transaction_type, reason, user["id"] if user else None, user["name"] if user else "System",
        request_id, order_id, po_id
    ))


def apply_location_delta(connection, product_id, delta=0, warehouse_id=None, bin_code=None, qc_delta=0, damaged_delta=0):
    """Keep location-level balances consistent with the authoritative product aggregate."""
    pid=int(product_id); delta=int(delta); qc_delta=int(qc_delta); damaged_delta=int(damaged_delta)
    if delta < 0:
        locations=connection.execute("""
            SELECT * FROM product_stock_locations WHERE product_id=?
            ORDER BY (on_hand-reserved-qc_hold-damaged) DESC, id ASC
        """,(pid,)).fetchall()
        remaining=abs(delta)
        for loc in locations:
            available=int(loc["on_hand"])-int(loc["reserved"])-int(loc["qc_hold"])-int(loc["damaged"])
            take=min(remaining,max(0,available))
            if take:
                connection.execute("UPDATE product_stock_locations SET on_hand=on_hand-? WHERE id=?",(take,loc["id"]))
                remaining-=take
            if remaining==0: break
        if remaining:
            raise ValueError("Location-level inventory is insufficient for this operation.")
        return
    # Positive or state-only mutation: choose requested warehouse/bin, otherwise primary location.
    loc=None
    if warehouse_id is not None and bin_code:
        loc=connection.execute("SELECT * FROM product_stock_locations WHERE product_id=? AND warehouse_id=? AND bin_code=?",(pid,int(warehouse_id),bin_code)).fetchone()
    if not loc and warehouse_id is not None:
        loc=connection.execute("SELECT * FROM product_stock_locations WHERE product_id=? AND warehouse_id=? ORDER BY id LIMIT 1",(pid,int(warehouse_id))).fetchone()
    if not loc:
        loc=connection.execute("SELECT * FROM product_stock_locations WHERE product_id=? ORDER BY on_hand DESC,id LIMIT 1",(pid,)).fetchone()
    if not loc:
        wid=int(warehouse_id or 1)
        bc=bin_code or ("DEL-R01-S01-B01" if wid==1 else f"WH{wid}-AUTO-BIN")
        connection.execute("INSERT INTO product_stock_locations(product_id,warehouse_id,bin_code,on_hand,reserved,qc_hold,damaged) VALUES(?,?,?,?,?,?,?)",(pid,wid,bc,max(0,delta),0,max(0,qc_delta),max(0,damaged_delta)))
        return
    connection.execute("""
        UPDATE product_stock_locations
        SET on_hand=MAX(0,on_hand+?), qc_hold=MAX(0,qc_hold+?), damaged=MAX(0,damaged+?)
        WHERE id=?
    """,(delta,qc_delta,damaged_delta,loc["id"]))

def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        return None
    user = sessions.get(token)
    now = datetime.now()
    if user:
        if (now - user["issued_at"]).total_seconds() > SESSION_TTL_MINUTES * 60:
            sessions.pop(token, None)
            with db() as connection:
                connection.execute("UPDATE user_sessions SET status='Expired', last_active=? WHERE session_token=?", (now.isoformat(), token))
            return None
        return {k: v for k, v in user.items() if k != "issued_at"}

    # Recover valid sessions after a server restart.
    cutoff = (now - timedelta(minutes=SESSION_TTL_MINUTES)).isoformat()
    row = one("""
        SELECT u.id,u.name,u.email,u.role,u.active,s.session_token,s.last_active,s.status
        FROM user_sessions s JOIN users u ON u.id=s.user_id
        WHERE s.session_token=? AND s.status='Active' AND s.last_active>=?
    """, (token, cutoff))
    if not row or not row["active"]:
        return None
    session_user = {
        "id": row["id"], "name": row["name"], "email": row["email"],
        "role": row["role"], "active": row["active"], "issued_at": now
    }
    sessions[token] = session_user
    return {k: v for k, v in session_user.items() if k != "issued_at"}


ROLE_PERMISSIONS = {
    "Owner": {"*"},
    "General Manager": {
        "product.view","product.create","product.update","product.archive",
        "inventory.view","inventory.receive","inventory.transfer","inventory.adjust",
        "request.create","request.review","request.approve","request.reject",
        "purchase.create","purchase.approve","reports.export","audit.view",
        "user.view","analytics.view"
    },
    "Lower-Level Manager": {
        "product.view","inventory.view","inventory.receive","inventory.transfer",
        "request.create","request.review","request.approve","request.reject",
        "purchase.view","reports.view","audit.view","analytics.view",
        "stocktake.review","return.inspect"
    },
    "Handler": {
        "product.view","inventory.view","inventory.receive","inventory.transfer",
        "request.create","stocktake.count","order.fulfill"
    },
}

# Governance permissions: suppliers are visible to Owner/GM; only Owner can manage them.
ROLE_PERMISSIONS["Owner"].update({"supplier.view", "supplier.manage", "transfer.request", "transfer.approve"})
ROLE_PERMISSIONS["General Manager"].update({"supplier.view", "transfer.request", "transfer.approve"})
ROLE_PERMISSIONS["Lower-Level Manager"].update({"transfer.request"})

def has_permission(user, permission):
    return bool(user and ("*" in ROLE_PERMISSIONS.get(user["role"], set()) or permission in ROLE_PERMISSIONS.get(user["role"], set())))

def require_permission(permission=None, *allowed_roles):
    def decorator(handler):
        @wraps(handler)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify(error="Please sign in to continue."), 401
            if allowed_roles and user["role"] not in allowed_roles:
                return jsonify(error="You do not have access to this action."), 403
            if permission and not has_permission(user, permission):
                return jsonify(error="You do not have permission for this action."), 403
            return handler(*args, **kwargs)
        return wrapped
    return decorator

def require_roles(*allowed_roles):
    return require_permission(None, *allowed_roles)

def init_db():
    with db() as connection:
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS warehouses (
            id INTEGER PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            city TEXT NOT NULL,
            manager_name TEXT NOT NULL,
            capacity_sqft INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS warehouse_bins (
            id INTEGER PRIMARY KEY,
            warehouse_id INTEGER NOT NULL,
            rack TEXT NOT NULL,
            shelf TEXT NOT NULL,
            bin_code TEXT UNIQUE NOT NULL,
            FOREIGN KEY(warehouse_id) REFERENCES warehouses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS suppliers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            contact_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            category TEXT NOT NULL,
            lead_time_days INTEGER NOT NULL DEFAULT 7,
            on_time_rate REAL NOT NULL DEFAULT 95.0,
            defect_rate REAL NOT NULL DEFAULT 1.2,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            sku TEXT UNIQUE NOT NULL,
            barcode TEXT UNIQUE,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT NOT NULL DEFAULT 'General',
            supplier_id INTEGER,
            price REAL NOT NULL,
            unit_cost REAL NOT NULL DEFAULT 0.0,
            on_hand INTEGER NOT NULL DEFAULT 0,
            reserved_qty INTEGER NOT NULL DEFAULT 0,
            qc_hold_qty INTEGER NOT NULL DEFAULT 0,
            damaged_qty INTEGER NOT NULL DEFAULT 0,
            reorder_point INTEGER NOT NULL DEFAULT 10,
            safety_stock INTEGER NOT NULL DEFAULT 5,
            lead_time_days INTEGER NOT NULL DEFAULT 7,
            expiry_date TEXT,
            image_url TEXT,
            monthly_sales INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'Active',
            FOREIGN KEY(supplier_id) REFERENCES suppliers(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS product_variants (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            sku TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            barcode TEXT UNIQUE NOT NULL,
            attributes TEXT NOT NULL,
            price REAL NOT NULL,
            unit_cost REAL NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS product_stock_locations (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL,
            bin_code TEXT NOT NULL,
            on_hand INTEGER NOT NULL DEFAULT 0,
            reserved INTEGER NOT NULL DEFAULT 0,
            qc_hold INTEGER NOT NULL DEFAULT 0,
            damaged INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY(warehouse_id) REFERENCES warehouses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS product_batches (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL,
            batch_number TEXT NOT NULL,
            mfg_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY(warehouse_id) REFERENCES warehouses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS product_serials (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            serial_number TEXT UNIQUE NOT NULL,
            warehouse_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'In-Stock',
            order_id INTEGER,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY(warehouse_id) REFERENCES warehouses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS stock_transfers (
            id INTEGER PRIMARY KEY,
            transfer_number TEXT UNIQUE NOT NULL,
            from_warehouse_id INTEGER NOT NULL,
            to_warehouse_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'Requested',
            created_by TEXT NOT NULL,
            dispatched_at TEXT,
            received_at TEXT,
            notes TEXT,
            FOREIGN KEY(from_warehouse_id) REFERENCES warehouses(id),
            FOREIGN KEY(to_warehouse_id) REFERENCES warehouses(id)
        );

        CREATE TABLE IF NOT EXISTS stock_transfer_items (
            id INTEGER PRIMARY KEY,
            transfer_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            FOREIGN KEY(transfer_id) REFERENCES stock_transfers(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            order_number TEXT UNIQUE NOT NULL,
            customer_name TEXT NOT NULL,
            customer_email TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            total_amount REAL NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            subtotal REAL NOT NULL,
            FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS returns (
            id INTEGER PRIMARY KEY,
            return_number TEXT UNIQUE NOT NULL,
            order_id INTEGER NOT NULL,
            customer_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Received',
            created_at TEXT NOT NULL,
            FOREIGN KEY(order_id) REFERENCES orders(id)
        );

        CREATE TABLE IF NOT EXISTS return_items (
            id INTEGER PRIMARY KEY,
            return_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            condition TEXT NOT NULL DEFAULT 'New',
            disposition TEXT NOT NULL DEFAULT 'Pending',
            inspected_by TEXT,
            notes TEXT,
            FOREIGN KEY(return_id) REFERENCES returns(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS purchase_orders (
            id INTEGER PRIMARY KEY,
            po_number TEXT UNIQUE NOT NULL,
            supplier_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'Ordered',
            total_cost REAL NOT NULL,
            expected_date TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            received_at TEXT,
            FOREIGN KEY(supplier_id) REFERENCES suppliers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS purchase_order_items (
            id INTEGER PRIMARY KEY,
            po_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            ordered_quantity INTEGER NOT NULL,
            received_quantity INTEGER NOT NULL DEFAULT 0,
            pending_quantity INTEGER NOT NULL,
            unit_cost REAL NOT NULL,
            FOREIGN KEY(po_id) REFERENCES purchase_orders(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS stocktakes (
            id INTEGER PRIMARY KEY,
            stocktake_number TEXT UNIQUE NOT NULL,
            warehouse_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'In-Progress',
            performed_by TEXT NOT NULL,
            approved_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(warehouse_id) REFERENCES warehouses(id)
        );

        CREATE TABLE IF NOT EXISTS stocktake_items (
            id INTEGER PRIMARY KEY,
            stocktake_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            system_qty INTEGER NOT NULL,
            counted_qty INTEGER NOT NULL,
            discrepancy INTEGER NOT NULL,
            reconciled INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(stocktake_id) REFERENCES stocktakes(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS stock_requests (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            request_type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            reviewed_by TEXT,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS inventory_transactions (
            transaction_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            batch_id INTEGER,
            serial_id INTEGER,
            source_warehouse_id INTEGER,
            source_bin TEXT,
            dest_warehouse_id INTEGER,
            dest_bin TEXT,
            before_qty INTEGER NOT NULL,
            delta_qty INTEGER NOT NULL,
            after_qty INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            reason TEXT,
            user_id INTEGER,
            operator TEXT NOT NULL,
            request_id INTEGER,
            order_id INTEGER,
            po_id INTEGER,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS movements (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sales_history (
            id INTEGER PRIMARY KEY,
            product_id INTEGER NOT NULL,
            sale_date TEXT NOT NULL,
            units_sold INTEGER NOT NULL,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        
        CREATE VIEW IF NOT EXISTS product_inventory_status AS
        SELECT 
            id as product_id,
            on_hand,
            reserved_qty,
            qc_hold_qty,
            damaged_qty,
            (on_hand - reserved_qty - qc_hold_qty - damaged_qty) as available_qty
        FROM products;
        
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            warehouse_id INTEGER,
            quantity INTEGER NOT NULL CHECK(quantity > 0),
            status TEXT NOT NULL DEFAULT 'Active',
            created_at TEXT NOT NULL,
            released_at TEXT,
            UNIQUE(order_id, product_id),
            FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS fulfillment_events (
            id INTEGER PRIMARY KEY,
            order_id INTEGER NOT NULL,
            from_status TEXT NOT NULL,
            to_status TEXT NOT NULL,
            operator_id INTEGER,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            ip_address TEXT NOT NULL,
            location TEXT NOT NULL,
            device_info TEXT NOT NULL,
            login_time TEXT NOT NULL,
            last_active TEXT NOT NULL,
            current_activity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Active',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            location TEXT,
            device_info TEXT,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            role TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            before_json TEXT,
            after_json TEXT,
            reason TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            priority TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            read_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS request_history (
            id INTEGER PRIMARY KEY,
            request_id INTEGER NOT NULL,
            actor_id INTEGER NOT NULL,
            from_status TEXT,
            to_status TEXT NOT NULL,
            comment TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id) REFERENCES stock_requests(id) ON DELETE CASCADE,
            FOREIGN KEY(actor_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS approvals (
            id INTEGER PRIMARY KEY,
            request_id INTEGER NOT NULL,
            reviewer_id INTEGER NOT NULL,
            decision TEXT NOT NULL,
            comment TEXT,
            previous_state TEXT,
            new_state TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(request_id) REFERENCES stock_requests(id) ON DELETE CASCADE,
            FOREIGN KEY(reviewer_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);
        CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(barcode);
        CREATE INDEX IF NOT EXISTS idx_transactions_product_time ON inventory_transactions(product_id,timestamp);
        CREATE INDEX IF NOT EXISTS idx_transactions_type ON inventory_transactions(transaction_type);
        CREATE INDEX IF NOT EXISTS idx_sales_product_date ON sales_history(product_id,sale_date);
        CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token);
        CREATE INDEX IF NOT EXISTS idx_requests_status ON stock_requests(status);
        CREATE INDEX IF NOT EXISTS idx_approvals_request ON approvals(request_id);
        """)
        for ddl in (
            "ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN locked_until TEXT",
            "ALTER TABLE products ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0"
        ):
            try:
                connection.execute(ddl)
            except sqlite3.OperationalError:
                pass

        # Runtime schema extensions used by the live 5-year dataset and frontend.
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS qc_inspections (
            id INTEGER PRIMARY KEY,
            purchase_order_id INTEGER,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            accepted_quantity INTEGER NOT NULL DEFAULT 0,
            rejected_quantity INTEGER NOT NULL DEFAULT 0,
            damaged_quantity INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'Pending',
            inspector_id INTEGER,
            reason TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(product_id) REFERENCES products(id)
        );
        CREATE INDEX IF NOT EXISTS idx_sales_date_product ON sales_history(sale_date, product_id);
        CREATE INDEX IF NOT EXISTS idx_tx_timestamp_product ON inventory_transactions(timestamp, product_id);
        CREATE INDEX IF NOT EXISTS idx_orders_created_status ON orders(created_at, status);
        CREATE INDEX IF NOT EXISTS idx_po_status_expected ON purchase_orders(status, expected_date);
        CREATE INDEX IF NOT EXISTS idx_requests_status ON stock_requests(status);
        CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, read_at);
        """)

        # Compatibility migrations for supplier lifecycle and warehouse transfer approvals.
        request_cols = {r[1] for r in connection.execute("PRAGMA table_info(stock_requests)").fetchall()}
        for col in ("source_warehouse_id", "destination_warehouse_id", "transfer_id"):
            if col not in request_cols:
                connection.execute(f"ALTER TABLE stock_requests ADD COLUMN {col} INTEGER")
        supplier_cols = {r[1] for r in connection.execute("PRAGMA table_info(suppliers)").fetchall()}
        if "active" not in supplier_cols:
            connection.execute("ALTER TABLE suppliers ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
        if "archived_at" not in supplier_cols:
            connection.execute("ALTER TABLE suppliers ADD COLUMN archived_at TEXT")

        # Check if already seeded
        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count > 0:
            return

        password = generate_password_hash("demo123")
        connection.executemany("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)", [
            ("Ananya Mehta", "owner@stocksphere.demo", password, "Owner"),
            ("Rahul Verma", "manager@stocksphere.demo", password, "General Manager"),
            ("Neha Kapoor", "ops@stocksphere.demo", password, "Lower-Level Manager"),
            ("Kiran Shah", "handler@stocksphere.demo", password, "Handler"),
        ])

        today = date.today()

        # Seed Warehouses
        connection.executemany("""
            INSERT INTO warehouses(code, name, city, manager_name, capacity_sqft)
            VALUES(?,?,?,?,?)
        """, [
            ("WH-DEL", "Delhi Central Hub", "Delhi", "Amit Saxena", 45000),
            ("WH-MRD", "Moradabad Depot", "Moradabad", "Rajesh Kumar", 25000),
            ("WH-LKO", "Lucknow Express Hub", "Lucknow", "Sunita Rao", 30000)
        ])

        # Seed Bins
        bins_data = [
            (1, "R01", "S01", "DEL-R01-S01-B01"),
            (1, "R02", "S03", "DEL-R02-S03-B14"),
            (1, "R03", "S02", "DEL-R03-S02-B17"),
            (2, "R01", "S02", "MRD-R01-S02-B08"),
            (2, "R02", "S01", "MRD-R02-S01-B04"),
            (3, "R01", "S03", "LKO-R01-S03-B12"),
            (3, "R02", "S02", "LKO-R02-S02-B09"),
        ]
        connection.executemany("INSERT INTO warehouse_bins(warehouse_id, rack, shelf, bin_code) VALUES(?,?,?,?)", bins_data)

        # Seed Suppliers
        suppliers_data = [
            ("Nova Supplies", "Vikram Rao", "vikram@novasupplies.demo", "+91-98765-43210", "Electronics", 7, 94.5, 1.2, (today - timedelta(days=90)).isoformat()),
            ("CraftLine Global", "Priya Sen", "priya@craftline.demo", "+91-98234-56789", "Home & Living", 10, 91.0, 2.1, (today - timedelta(days=90)).isoformat()),
            ("GlowLab Organics", "Maya Nair", "maya@glowlab.demo", "+91-98123-45678", "Beauty", 5, 96.2, 0.8, (today - timedelta(days=90)).isoformat()),
            ("Green Harvest Naturals", "Arvind Pillai", "arvind@greenharvest.demo", "+91-98345-67890", "Food & Beverage", 4, 98.0, 0.5, (today - timedelta(days=90)).isoformat()),
            ("Thread & Co Apparel", "Simran Kaur", "simran@threadco.demo", "+91-98456-78901", "Fashion", 12, 88.5, 3.4, (today - timedelta(days=90)).isoformat()),
        ]
        connection.executemany("""
            INSERT INTO suppliers(name, contact_name, email, phone, category, lead_time_days, on_time_rate, defect_rate, created_at)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, suppliers_data)

        # Seed Products
        products_data = [
            ("ELC-101", "890123450001", "Aurora Wireless Headphones", "Electronics", "Audio & Wearables", 1, 3499.0, 1850.0, 14, 0, 0, 0, 10, 5, 7, (today + timedelta(days=180)).isoformat(), "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=240&auto=format&fit=crop&q=80", 86),
            ("HOM-204", "890123450002", "Linen Storage Basket", "Home & Living", "Storage & Decor", 2, 899.0, 420.0, 88, 0, 0, 0, 12, 5, 10, (today + timedelta(days=365)).isoformat(), "https://images.unsplash.com/photo-1595991209266-5ff5a3a2f008?w=240&auto=format&fit=crop&q=80", 52),
            ("BEA-309", "890123450003", "Vitamin C Face Serum", "Beauty", "Skincare", 3, 1299.0, 580.0, 8, 2, 0, 0, 8, 3, 5, (today + timedelta(days=15)).isoformat(), "https://images.unsplash.com/photo-1620916566398-39f1143ab7be?w=240&auto=format&fit=crop&q=80", 124),
            ("FOD-412", "890123450004", "Organic Trail Mix 500g", "Food & Beverage", "Snacks & Health", 4, 499.0, 210.0, 24, 0, 0, 0, 14, 5, 4, (today + timedelta(days=9)).isoformat(), "https://images.unsplash.com/photo-1599599810769-bcde5a160d32?w=240&auto=format&fit=crop&q=80", 97),
            ("FAS-518", "890123450005", "Everyday Canvas Tote", "Fashion", "Bags & Accessories", 5, 749.0, 310.0, 140, 5, 0, 0, 16, 5, 12, (today + timedelta(days=365)).isoformat(), "https://images.unsplash.com/photo-1544816155-12df9643f363?w=240&auto=format&fit=crop&q=80", 71),
            ("ELC-605", "890123450006", "USB-C Power Bank 20000mAh", "Electronics", "Charging Accessories", 1, 2199.0, 1150.0, 6, 0, 0, 0, 8, 5, 7, (today + timedelta(days=365)).isoformat(), "https://images.unsplash.com/photo-1609091839311-d5365f9ff1c5?w=240&auto=format&fit=crop&q=80", 109),
            ("HOM-312", "890123450007", "Bamboo Cooking Utensils Set", "Home & Living", "Kitchen Tools", 2, 599.0, 240.0, 5, 0, 0, 0, 6, 5, 10, (today + timedelta(days=365)).isoformat(), "https://images.unsplash.com/photo-1584269600464-37b1b58a9fe7?w=240&auto=format&fit=crop&q=80", 43),
            ("BEA-102", "890123450008", "Botanical Glow Night Cream", "Beauty", "Skincare", 3, 899.0, 390.0, 52, 0, 0, 0, 8, 5, 5, (today + timedelta(days=220)).isoformat(), "https://images.unsplash.com/photo-1556228720-195a672e8a03?w=240&auto=format&fit=crop&q=80", 64),
        ]
        connection.executemany("""
            INSERT INTO products(sku, barcode, name, category, subcategory, supplier_id, price, unit_cost, on_hand, reserved_qty, qc_hold_qty, damaged_qty, reorder_point, safety_stock, lead_time_days, expiry_date, image_url, monthly_sales)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, products_data)

        # Seed Product Variants
        variants_data = [
            (1, "ELC-101-BLK", "Aurora Wireless Headphones - Matte Black", "890123450101", "Color: Matte Black", 3499.0, 1850.0, 8),
            (1, "ELC-101-SLV", "Aurora Wireless Headphones - Silver White", "890123450102", "Color: Silver White", 3499.0, 1850.0, 6),
            (5, "FAS-518-NAT", "Everyday Canvas Tote - Natural", "890123450501", "Color: Natural Off-White", 749.0, 310.0, 80),
            (5, "FAS-518-BLK", "Everyday Canvas Tote - Midnight Black", "890123450502", "Color: Midnight Black", 749.0, 310.0, 60),
        ]
        connection.executemany("""
            INSERT INTO product_variants(product_id, sku, name, barcode, attributes, price, unit_cost, stock)
            VALUES(?,?,?,?,?,?,?,?)
        """, variants_data)

        # Seed Multi-Warehouse Stock Locations (Delhi, Moradabad, Lucknow)
        locations_data = [
            (1, 1, "DEL-R03-S02-B17", 10, 2, 0, 0),
            (1, 2, "MRD-R01-S02-B08", 4, 0, 0, 0),
            (2, 1, "DEL-R01-S01-B01", 50, 3, 0, 0),
            (2, 2, "MRD-R02-S01-B04", 20, 1, 0, 0),
            (2, 3, "LKO-R01-S03-B12", 18, 1, 0, 0),
            (3, 1, "DEL-R02-S03-B14", 5, 2, 0, 0),
            (3, 2, "MRD-R01-S02-B08", 3, 1, 0, 0),
            (4, 1, "DEL-R02-S03-B14", 16, 2, 0, 0),
            (4, 3, "LKO-R02-S02-B09", 8, 2, 0, 0),
            (5, 1, "DEL-R01-S01-B01", 70, 4, 0, 0),
            (5, 2, "MRD-R02-S01-B04", 40, 2, 0, 0),
            (5, 3, "LKO-R01-S03-B12", 30, 2, 0, 0),
            (6, 1, "DEL-R03-S02-B17", 4, 1, 0, 0),
            (6, 2, "MRD-R01-S02-B08", 2, 1, 0, 0),
            (7, 1, "DEL-R01-S01-B01", 3, 1, 0, 0),
            (7, 3, "LKO-R02-S02-B09", 2, 0, 0, 0),
            (8, 1, "DEL-R02-S03-B14", 32, 4, 0, 0),
            (8, 3, "LKO-R01-S03-B12", 20, 2, 0, 0),
        ]
        connection.executemany("""
            INSERT INTO product_stock_locations(product_id, warehouse_id, bin_code, on_hand, reserved, qc_hold, damaged)
            VALUES(?,?,?,?,?,?,?)
        """, locations_data)

        # Seed Batches for FEFO
        batches_data = [
            (3, 1, "BATCH-BEA-2026A", (today - timedelta(days=45)).isoformat(), (today + timedelta(days=15)).isoformat(), 5),
            (3, 2, "BATCH-BEA-2026B", (today - timedelta(days=20)).isoformat(), (today + timedelta(days=60)).isoformat(), 3),
            (4, 1, "BATCH-FOD-9901", (today - timedelta(days=60)).isoformat(), (today + timedelta(days=9)).isoformat(), 14),
            (4, 3, "BATCH-FOD-9902", (today - timedelta(days=15)).isoformat(), (today + timedelta(days=90)).isoformat(), 10),
        ]
        connection.executemany("""
            INSERT INTO product_batches(product_id, warehouse_id, batch_number, mfg_date, expiry_date, quantity)
            VALUES(?,?,?,?,?,?)
        """, batches_data)

        # Seed Serial Numbers
        serials_data = [
            (1, "SN-ELC-8801", 1, "In-Stock", None),
            (1, "SN-ELC-8802", 1, "In-Stock", None),
            (1, "SN-ELC-8803", 1, "Reserved", 1),
            (1, "SN-ELC-8804", 1, "Sold", 1),
            (6, "SN-PB-9011", 1, "In-Stock", None),
            (6, "SN-PB-9012", 2, "In-Stock", None),
        ]
        connection.executemany("""
            INSERT INTO product_serials(product_id, serial_number, warehouse_id, status, order_id)
            VALUES(?,?,?,?,?)
        """, serials_data)

        # Seed Stock Transfers
        connection.execute("""
            INSERT INTO stock_transfers(transfer_number, from_warehouse_id, to_warehouse_id, status, created_by, dispatched_at, notes)
            VALUES(?,?,?,?,?,?,?)
        """, ("TRF-2026-0042", 1, 2, "In-Transit", "Neha Kapoor", (datetime.now() - timedelta(hours=6)).isoformat(), "Emergency stock rebalance from Delhi to Moradabad depot"))
        connection.execute("INSERT INTO stock_transfer_items(transfer_id, product_id, quantity) VALUES(1, 1, 10)")

        # Seed Initial Order (Required for Returns foreign key)
        connection.execute("""
            INSERT INTO orders(order_number, customer_name, customer_email, status, total_amount, created_at)
            VALUES(?,?,?,?,?,?)
        """, ("ORD-2026-1001", "Rohan Sharma", "rohan.sharma@example.com", "Shipped", 6998.0, (datetime.now() - timedelta(days=2)).isoformat()))
        connection.execute("""
            INSERT INTO order_items(order_id, product_id, quantity, unit_price, subtotal)
            VALUES(1, 1, 2, 3499.0, 6998.0)
        """)

        # Seed Returns & Inspection
        connection.execute("""
            INSERT INTO returns(return_number, order_id, customer_name, status, created_at)
            VALUES(?,?,?,?,?)
        """, ("RET-2026-0019", 1, "Rohan Sharma", "Under Inspection", (datetime.now() - timedelta(hours=3)).isoformat()))
        connection.execute("""
            INSERT INTO return_items(return_id, product_id, quantity, condition, disposition, notes)
            VALUES(1, 1, 1, 'Minor Damage', 'Pending', 'Outer box opened; technician checking ear cushions')
        """)

        # Seed Purchase Orders with Partial Receiving (e.g. PO #1042)
        connection.execute("""
            INSERT INTO purchase_orders(po_number, supplier_id, status, total_cost, expected_date, created_by, created_at)
            VALUES(?,?,?,?,?,?,?)
        """, ("PO-2026-1042", 1, "Partially Received", 92500.0, (today + timedelta(days=2)).isoformat(), "Rahul Verma", (datetime.now() - timedelta(days=5)).isoformat()))
        connection.execute("""
            INSERT INTO purchase_order_items(po_id, product_id, ordered_quantity, received_quantity, pending_quantity, unit_cost)
            VALUES(1, 1, 50, 35, 15, 1850.0)
        """)

        # Seed Stocktakes
        connection.execute("""
            INSERT INTO stocktakes(stocktake_number, warehouse_id, status, performed_by, created_at)
            VALUES(?,?,?,?,?)
        """, ("ST-2026-081", 1, "In-Progress", "Kiran Shah", datetime.now().isoformat()))
        connection.execute("""
            INSERT INTO stocktake_items(stocktake_id, product_id, system_qty, counted_qty, discrepancy, reconciled)
            VALUES(1, 1, 10, 8, -2, 0)
        """)

        # Seed Continuous Audit Ledger ("Why Did Stock Change?")
        ledger_sample = [
            (str(uuid.uuid4()), (datetime.now() - timedelta(days=40)).isoformat(), "System", 1, 1, "DEL-R03-S02-B17", "Opening Stock", 0, 30, 30, "Initial warehouse intake", None, 1),
            (str(uuid.uuid4()), (datetime.now() - timedelta(days=20)).isoformat(), "Kiran Shah", 1, 1, "DEL-R03-S02-B17", "Purchase Received", 30, 50, 80, "PO #PO-2026-0801 arrival", None, 4),
            (str(uuid.uuid4()), (datetime.now() - timedelta(days=5)).isoformat(), "Kiran Shah", 1, 1, "DEL-R03-S02-B17", "Customer Sales", 80, -60, 20, "Batch fulfillment for B2C orders", None, 4),
            (str(uuid.uuid4()), (datetime.now() - timedelta(days=2)).isoformat(), "Kiran Shah", 1, 1, "DEL-R03-S02-B17", "Damaged", 20, -2, 18, "Handling transit dent", None, 4),
            (str(uuid.uuid4()), (datetime.now() - timedelta(days=1)).isoformat(), "Kiran Shah", 1, 1, "DEL-R03-S02-B17", "Transfer Out", 18, -4, 14, "Stock rebalance to Moradabad", None, 4),
        ]
        connection.executemany("""
            INSERT INTO inventory_transactions(transaction_id, timestamp, operator, product_id, source_warehouse_id, source_bin, transaction_type, before_qty, delta_qty, after_qty, reason, order_id, user_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, ledger_sample)

        # Seed 90 days of realistic daily sales history for machine learning
        rng = np.random.default_rng(42)
        sales_records = []
        base_rates = {
            1: (3.0, 0.02, 1.2),
            2: (1.8, -0.005, 0.8),
            3: (4.2, 0.03, 1.5),
            4: (3.2, 0.01, 1.1),
            5: (2.4, 0.00, 1.0),
            6: (3.8, 0.025, 1.4),
            7: (1.5, 0.01, 0.7),
            8: (2.1, 0.005, 0.9),
        }

        for day_offset in range(90, 0, -1):
            cur_date = (today - timedelta(days=day_offset)).isoformat()
            t = 90 - day_offset
            for prod_id, (base, trend, noise_scale) in base_rates.items():
                expected = base + (trend * t)
                units = max(0, int(round(rng.normal(expected, noise_scale))))
                sales_records.append((prod_id, cur_date, units))

        connection.executemany("INSERT INTO sales_history(product_id, sale_date, units_sold) VALUES(?,?,?)", sales_records)

        # Seed initial Movements & Requests
        connection.executemany("INSERT INTO movements(product_id,kind,quantity,note,created_at,created_by) VALUES(?,?,?,?,?,?)", [
            (1, "Stock out", 4, "Customer Order #ORD-2026-1001", (datetime.now() - timedelta(days=1)).isoformat(), "Kiran Shah"),
            (3, "Stock in", 20, "PO Receipt #PO-2026-0801", (datetime.now() - timedelta(days=2)).isoformat(), "Kiran Shah"),
            (4, "Damaged", 2, "Transit packaging tear", (datetime.now() - timedelta(days=3)).isoformat(), "Kiran Shah"),
            (6, "Stock out", 5, "Customer Order #ORD-2026-1002", (datetime.now() - timedelta(days=2)).isoformat(), "Kiran Shah"),
        ])

        connection.executemany("INSERT INTO stock_requests(product_id,request_type,quantity,reason,status,created_by,created_at) VALUES(?,?,?,?,?,?,?)", [
            (6, "Restock", 40, "Critically low stock (6 units). High daily velocity.", "Pending", "Kiran Shah", datetime.now().isoformat()),
            (7, "Restock", 30, "Current stock (5 units) below safety threshold.", "Pending", "Kiran Shah", (datetime.now() - timedelta(hours=4)).isoformat()),
            (4, "Expiry alert", 10, "Batch expires in 9 days. Recommend markdown or bundle promotion.", "Pending", "Kiran Shah", (datetime.now() - timedelta(days=1)).isoformat()),
        ])

        # Seed Initial Active Sessions for Live Personnel Monitoring
        now_iso = datetime.now().isoformat()
        sessions_seed = [
            (1, "demo_token_owner", "192.168.1.10", "Saharanpur, UP, India", "Chrome 128 on Windows 11", now_iso, now_iso, "Monitoring Executive Valuation & Profit Trends", "Active"),
            (4, "demo_token_handler", "192.168.2.45", "Delhi Central Hub Floor", "CoreOS Mobile Floor Terminal", now_iso, now_iso, "Scanning Rack DEL-R03-S02-B17", "Active"),
            (3, "demo_token_ops", "192.168.3.12", "Moradabad Operations Desk", "Edge on Windows 11", now_iso, now_iso, "Reviewing Restock Request #REQ-002", "Active"),
            (2, "demo_token_gm", "192.168.1.15", "Saharanpur Corporate Office", "Safari on macOS Sonoma", now_iso, now_iso, "Inspecting Inbound PO #1042", "Active"),
        ]
        connection.executemany("""
            INSERT INTO user_sessions(user_id, session_token, ip_address, location, device_info, login_time, last_active, current_activity, status)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, sessions_seed)
# ==========================================
# AUTH & EXECUTIVE DASHBOARD (OWNER / GM)
# ==========================================

@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.post("/api/auth/login")
def login():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email", "")).strip().lower()
    password = payload.get("password", "")
    device = payload.get("device") or request.headers.get("User-Agent", "Unknown browser")
    location = payload.get("location") or "Unknown location"
    ip = request.remote_addr or "127.0.0.1"
    now = datetime.now()

    user = one("SELECT * FROM users WHERE lower(email)=?", (email,))
    if not user or not user["active"]:
        return jsonify(error="Incorrect email or password."), 401

    locked_until = user["locked_until"] if "locked_until" in user.keys() else None
    if locked_until:
        try:
            if now < datetime.fromisoformat(locked_until):
                return jsonify(error="Account temporarily locked. Try again later."), 423
        except ValueError:
            pass

    valid = check_password_hash(user["password_hash"], password)
    if not valid:
        failures = int(user["failed_login_count"] or 0) + 1
        lock = (now + timedelta(minutes=LOCKOUT_MINUTES)).isoformat() if failures >= MAX_FAILED_LOGINS else None
        with db() as connection:
            connection.execute("UPDATE users SET failed_login_count=?, locked_until=? WHERE id=?", (failures, lock, user["id"]))
            connection.execute("""
                INSERT INTO security_events(user_id,event_type,ip_address,location,device_info,details,created_at)
                VALUES(?,?,?,?,?,?,?)
            """, (user["id"], "FAILED_LOGIN", ip, location, device, f"failed_attempt={failures}", now.isoformat()))
            connection.execute("""
                INSERT INTO audit_logs(user_id,role,action,resource_type,resource_id,reason,created_at)
                VALUES(?,?,?,?,?,?,?)
            """, (user["id"], user["role"], "login.failed", "user", str(user["id"]), "Invalid credentials", now.isoformat()))
        return jsonify(error="Incorrect email or password." if not lock else "Too many failed attempts. Account temporarily locked."), 401 if not lock else 423

    user_dict = {k: user[k] for k in ("id","name","email","role","active")}
    with db() as connection:
        connection.execute("UPDATE users SET failed_login_count=0, locked_until=NULL WHERE id=?", (user["id"],))
        prev = connection.execute(
            "SELECT login_time,device_info,location FROM user_sessions WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (user["id"],),
        ).fetchone()
        token = secrets.token_urlsafe(32)
        now_str = now.isoformat()
        connection.execute("""
            INSERT INTO user_sessions(user_id,session_token,ip_address,location,device_info,login_time,last_active,current_activity,status)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, (user["id"], token, ip, location, device, now_str, now_str, f"Authenticated via Gateway ({user['role']})", "Active"))
        connection.execute("""
            INSERT INTO security_events(user_id,event_type,ip_address,location,device_info,details,created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (user["id"], "LOGIN_SUCCESS", ip, location, device, "Authentication succeeded", now_str))
        connection.execute("""
            INSERT INTO audit_logs(user_id,role,action,resource_type,resource_id,reason,created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (user["id"], user["role"], "login.success", "user", str(user["id"]), "Authentication succeeded", now_str))

    sessions[token] = {**user_dict, "issued_at": now}
    last_login = {
        "time": prev["login_time"] if prev else now_str,
        "device": prev["device_info"] if prev else device,
        "location": prev["location"] if prev else location,
    }
    return jsonify(token=token, user=user_dict, last_login=last_login)


@app.post("/api/auth/logout")
@require_permission()
def logout():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    user = current_user()
    sessions.pop(token, None)
    with db() as connection:
        connection.execute("UPDATE user_sessions SET status='Logged Out', last_active=? WHERE session_token=?", (datetime.now().isoformat(), token))
        if user:
            connection.execute("""
                INSERT INTO audit_logs(user_id,role,action,resource_type,resource_id,reason,created_at)
                VALUES(?,?,?,?,?,?,?)
            """, (user["id"],user["role"],"logout","session",token[:12],"User logout",datetime.now().isoformat()))
    return jsonify(message="Signed out successfully.")


@app.post("/api/auth/heartbeat")
@require_roles()
def auth_heartbeat():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    payload = request.get_json(silent=True) or {}
    activity = payload.get("activity", "Active in Workspace")
    with db() as connection:
        connection.execute("""
            UPDATE user_sessions
            SET last_active=?, current_activity=?, status='Active'
            WHERE session_token=?
        """, (datetime.now().isoformat(), activity, token))
    return jsonify(status="ok")


@app.get("/api/security/active-sessions")
@require_roles("Owner", "General Manager")
def get_active_sessions():
    cutoff = (datetime.now() - timedelta(minutes=20)).isoformat()
    sql = """
        SELECT s.id as session_id, s.user_id, s.ip_address, s.location, s.device_info,
               s.login_time, s.last_active, s.current_activity, s.status,
               u.name, u.email, u.role
        FROM user_sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.status='Active' AND s.last_active >= ?
        ORDER BY s.last_active DESC
    """
    active_list = rows(sql, (cutoff,))
    return jsonify(sessions=active_list, count=len(active_list))


@app.post("/api/security/terminate-session/<int:session_id>")
@require_roles("Owner", "General Manager")
def terminate_session(session_id):
    with db() as connection:
        sess = connection.execute("SELECT session_token FROM user_sessions WHERE id=?", (session_id,)).fetchone()
        if sess and sess["session_token"] in sessions:
            del sessions[sess["session_token"]]
        connection.execute("UPDATE user_sessions SET status='Terminated' WHERE id=?", (session_id,))
    return jsonify(message="Session terminated successfully.")


@app.get("/api/auth/me")
@require_roles()
def me():
    return jsonify(current_user())


@app.get("/api/dashboard/owner")
@require_permission("analytics.view")
def owner_dashboard():
    """Database-derived executive telemetry. No hardcoded business metrics."""
    today = date.today()
    products = rows("""
        SELECT p.*, s.name AS supplier_name
        FROM products p LEFT JOIN suppliers s ON p.supplier_id=s.id
        ORDER BY p.id
    """)
    po_incoming = one("SELECT COALESCE(SUM(poi.pending_quantity),0) AS n FROM purchase_order_items poi JOIN purchase_orders po ON po.id=poi.po_id WHERE po.status NOT IN ('Received','Closed','Cancelled')")
    total_products = len(products)
    total_on_hand = sum(int(p["on_hand"] or 0) for p in products)
    total_reserved = sum(int(p["reserved_qty"] or 0) for p in products)
    total_qc = sum(int(p["qc_hold_qty"] or 0) for p in products)
    total_damaged = sum(int(p["damaged_qty"] or 0) for p in products)
    available = sum(max(0, int(p["on_hand"] or 0) - int(p["reserved_qty"] or 0) - int(p["qc_hold_qty"] or 0) - int(p["damaged_qty"] or 0)) for p in products)
    inventory_value = sum(int(p["on_hand"] or 0) * float(p["unit_cost"] or 0) for p in products)

    month_start = today.replace(day=1).isoformat()
    sales_month = one("SELECT COALESCE(SUM(units_sold),0) AS units FROM sales_history WHERE sale_date>=?", (month_start,))
    orders_month = one("SELECT COUNT(*) AS n, COALESCE(SUM(total_amount),0) AS revenue FROM orders WHERE date(created_at)>=?", (month_start,))
    cogs_month = one("""
        SELECT COALESCE(SUM(oi.quantity * p.unit_cost),0) AS cogs
        FROM orders o JOIN order_items oi ON oi.order_id=o.id JOIN products p ON p.id=oi.product_id
        WHERE date(o.created_at)>=? AND o.status NOT IN ('Cancelled')
    """, (month_start,))
    todays_sales = one("SELECT COALESCE(SUM(oi.subtotal),0) AS revenue FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE date(o.created_at)=date('now') AND o.status NOT IN ('Cancelled')")
    revenue = float(orders_month["revenue"] or 0)
    cogs = float(cogs_month["cogs"] or 0)
    gross_profit = revenue - cogs
    low_count = sum(1 for p in products if int(p["on_hand"] or 0) - int(p["reserved_qty"] or 0) <= int(p["reorder_point"] or 0))
    expiring_count = sum(1 for p in products if p["expiry_date"] and p["expiry_date"] <= (today + timedelta(days=30)).isoformat())
    health_counts = {"Healthy":0,"Attention":0,"Critical":0}
    for p in products:
        avail = int(p["on_hand"] or 0) - int(p["reserved_qty"] or 0) - int(p["qc_hold_qty"] or 0) - int(p["damaged_qty"] or 0)
        rop = int(p["reorder_point"] or 0)
        if avail <= max(0, rop // 2): health_counts["Critical"] += 1
        elif avail <= rop: health_counts["Attention"] += 1
        else: health_counts["Healthy"] += 1
    denom=max(1,total_products)
    health={k:round(v*100/denom,1) for k,v in health_counts.items()}

    # Twelve-month operational trend from daily sales history, valued against live product price/cost.
    trend_rows = rows("""
        SELECT substr(s.sale_date,1,7) AS ym,
               SUM(s.units_sold) AS units,
               SUM(s.units_sold * p.price) AS revenue,
               SUM(s.units_sold * p.unit_cost) AS cogs
        FROM sales_history s JOIN products p ON p.id=s.product_id
        WHERE s.sale_date >= date('now','-12 months','start of month')
        GROUP BY ym ORDER BY ym
    """)
    labels=[r["ym"] for r in trend_rows]
    units=[int(r["units"] or 0) for r in trend_rows]
    revenue_trend=[round(float(r["revenue"] or 0),2) for r in trend_rows]
    profits_trend=[round(float(r["revenue"] or 0)-float(r["cogs"] or 0),2) for r in trend_rows]

    category_rows=rows("""
        SELECT category, COUNT(*) product_count, SUM(on_hand) units,
               SUM(on_hand*unit_cost) inventory_value
        FROM products GROUP BY category ORDER BY inventory_value DESC
    """)
    warehouse_rows=rows("""
        SELECT w.id,w.name,w.city,
               COALESCE(SUM(psl.on_hand),0) units,
               COALESCE(SUM(psl.on_hand*p.unit_cost),0) inventory_value,
               COUNT(DISTINCT psl.product_id) product_count
        FROM warehouses w
        LEFT JOIN product_stock_locations psl ON psl.warehouse_id=w.id
        LEFT JOIN products p ON p.id=psl.product_id
        WHERE w.active=1
        GROUP BY w.id ORDER BY inventory_value DESC
    """)
    supplier_summary=one("""
        SELECT COUNT(*) active_suppliers, ROUND(AVG(lead_time_days),1) avg_lead_time,
               ROUND(AVG(on_time_rate),1) avg_on_time_rate, ROUND(AVG(defect_rate),2) avg_defect_rate
        FROM suppliers
    """)
    critical = sorted(
        [{"product_id":p["id"],"product":p["name"],"sku":p["sku"],"available":int(p["on_hand"] or 0)-int(p["reserved_qty"] or 0),"rop":int(p["reorder_point"] or 0)}
         for p in products if int(p["on_hand"] or 0)-int(p["reserved_qty"] or 0) <= int(p["reorder_point"] or 0)],
        key=lambda x:(x["available"]-x["rop"])
    )[:10]

    recent_pos=rows("SELECT id,po_number,status,total_cost,supplier_id FROM purchase_orders ORDER BY id DESC LIMIT 5")
    for po in recent_pos:
        po["supplier"] = one("SELECT name FROM suppliers WHERE id=?", (po["supplier_id"],))["name"]

    return jsonify({
        "kpis":{
            "total_products":total_products,"total_inventory":total_on_hand,"available_units":available,
            "reserved_units":total_reserved,"incoming_units":int(po_incoming["n"] or 0),
            "inventory_value":round(inventory_value,2),"todays_sales":round(float(todays_sales["revenue"] or 0),2),
            "monthly_revenue":round(revenue,2),"gross_profit":round(gross_profit,2),
            "low_stock_count":low_count,"expiring_soon_count":expiring_count
        },
        "health":{ "healthy_pct":health["Healthy"],"attention_pct":health["Attention"],"critical_pct":health["Critical"]},
        "sales_trend":{"labels":labels,"revenue":revenue_trend,"profits":profits_trend,"units":units},
        "category_dist":[{"name":r["category"],"product_count":r["product_count"],"units":r["units"],"value":round(r["inventory_value"] or 0,2)} for r in category_rows],
        "warehouses":[dict(r) for r in warehouse_rows],
        "risks":{"low_stock":critical,"expiry_count":expiring_count,"dead_stock_value":round(sum(float(p["on_hand"] or 0)*float(p["unit_cost"] or 0) for p in products if (p["monthly_sales"] or 0)==0),2)},
        "supplier_summary":dict(supplier_summary or {}),
        "recent_purchase_orders":recent_pos
    })


@app.get("/api/dashboard/handler")
@require_roles("Handler")
def handler_dashboard():
    user=current_user()
    products=rows("SELECT id,name,sku,on_hand,reserved_qty,qc_hold_qty,damaged_qty,reorder_point FROM products ORDER BY id")
    low=[{"product_id":p["id"],"product":p["name"],"sku":p["sku"],"available":max(0,int(p["on_hand"])-int(p["reserved_qty"])-int(p["qc_hold_qty"])-int(p["damaged_qty"])),"rop":int(p["reorder_point"])} for p in products if max(0,int(p["on_hand"])-int(p["reserved_qty"])-int(p["qc_hold_qty"])-int(p["damaged_qty"]))<=int(p["reorder_point"])]
    return jsonify({
        "role":"Handler",
        "focus":"Today’s floor work",
        "pending_requests":one("SELECT COUNT(*) n FROM stock_requests WHERE created_by=? AND status IN ('Pending','UNDER REVIEW')",(user["name"],))["n"],
        "my_recent_requests":rows("SELECT r.*,p.name product_name,p.sku FROM stock_requests r JOIN products p ON p.id=r.product_id WHERE r.created_by=? ORDER BY r.id DESC LIMIT 8",(user["name"],)),
        "alerts":sorted(low,key=lambda x:x["available"]-x["rop"])[:8],
        "open_pos":one("SELECT COUNT(*) n FROM purchase_orders WHERE status NOT IN ('Received','Closed','Cancelled')")["n"],
        "today_receipts":one("SELECT COUNT(*) n FROM qc_inspections WHERE date(created_at)=date('now')")["n"]
    })


@app.get("/api/dashboard")
@require_permission("analytics.view")
def role_dashboard():
    base = owner_dashboard().get_json()
    role = current_user()["role"]
    extra = {}
    if role == "Handler":
        extra = {
            "focus":"Today’s floor work",
            "actions": ["Scan","Receive","Move stock","Count","Pick","Pack","Return"],
            "pending_requests": one("SELECT COUNT(*) n FROM stock_requests WHERE created_by=? AND status IN ('Pending','UNDER REVIEW')",(current_user()["name"],))["n"],
            "alerts": base["risks"]["low_stock"][:5]
        }
    elif role == "Lower-Level Manager":
        extra = {
            "focus":"What needs my attention?",
            "pending_requests": one("SELECT COUNT(*) n FROM stock_requests WHERE status IN ('Pending','UNDER REVIEW')")["n"],
            "stocktakes_open": one("SELECT COUNT(*) n FROM stocktakes WHERE status!='Completed'")["n"],
            "returns_open": one("SELECT COUNT(*) n FROM returns WHERE status!='Completed'")["n"]
        }
    elif role == "General Manager":
        extra = {
            "focus":"Business operations",
            "purchase_orders_open": one("SELECT COUNT(*) n FROM purchase_orders WHERE status NOT IN ('Received','Closed','Cancelled')")["n"],
            "warehouses": one("SELECT COUNT(*) n FROM warehouses WHERE active=1")["n"],
            "suppliers": one("SELECT COUNT(*) n FROM suppliers")["n"]
        }
    else:
        extra = {"focus":"Executive business overview","scope":"All business data"}
    base["role_dashboard"] = extra
    base["role"] = role
    return jsonify(base)


# ==========================================
# NATURAL-LANGUAGE "ASK THE DATA" API
# ==========================================

@app.post("/api/analytics/ask-data")
@require_permission("analytics.view")
def ask_data():
    query = (request.get_json(silent=True) or {}).get("query","").strip().lower()
    if not query:
        return jsonify(error="Ask a data question."), 400

    if "categor" in query:
        data=rows("""SELECT category AS Category, COUNT(*) AS SKUs,
                     SUM(on_hand) AS Units, ROUND(SUM(on_hand*unit_cost),2) AS InventoryValue
                     FROM products GROUP BY category ORDER BY InventoryValue DESC""")
        return jsonify(answer="Category valuation calculated from current product inventory and unit cost.", table=data, type="table")
    if "dead" in query or "slow" in query:
        cutoff=(date.today()-timedelta(days=60)).isoformat()
        data=rows("""SELECT p.sku AS SKU,p.name AS Product,p.on_hand AS Units,
                            ROUND(p.on_hand*p.unit_cost,2) AS LockedCapital,
                            MAX(sh.sale_date) AS LastSale
                     FROM products p LEFT JOIN sales_history sh ON sh.product_id=p.id
                     GROUP BY p.id
                     HAVING (LastSale IS NULL OR LastSale<?) AND p.on_hand>0
                     ORDER BY LockedCapital DESC""",(cutoff,))
        return jsonify(answer=f"{len(data)} products have had no recorded sale in the last 60 days.",table=data,type="table")
    if "risk" in query or "stockout" in query or "low" in query:
        data=rows("""SELECT sku AS SKU,name AS Product,
                            (on_hand-reserved_qty-qc_hold_qty-damaged_qty) AS Available,
                            reorder_point AS ROP
                     FROM products
                     WHERE (on_hand-reserved_qty-qc_hold_qty-damaged_qty)<=reorder_point
                     ORDER BY Available ASC""")
        return jsonify(answer=f"{len(data)} products are at or below their reorder point.",table=data,type="table")
    if "profit" in query or "revenue" in query or "margin" in query:
        data=one("""SELECT ROUND(COALESCE(SUM(oi.subtotal),0),2) revenue,
                           ROUND(COALESCE(SUM(oi.quantity*p.unit_cost),0),2) cogs
                    FROM orders o JOIN order_items oi ON oi.order_id=o.id JOIN products p ON p.id=oi.product_id
                    WHERE date(o.created_at)>=date('now','-30 day') AND o.status!='Cancelled'""")
        rev=float(data["revenue"] or 0); cogs=float(data["cogs"] or 0)
        gp=rev-cogs
        return jsonify(answer=f"Last 30 days: revenue ₹{rev:,.2f}, gross profit ₹{gp:,.2f}, margin {(gp/rev*100 if rev else 0):.1f}%.", type="text")
    return jsonify(answer="I can answer category, dead-stock, stockout-risk, revenue, profit, and margin questions from the live database.",type="text")


# ==========================================
# "WHY DID STOCK CHANGE?" EXPLAINER LEDGER
# ==========================================

@app.get("/api/products/<int:product_id>/ledger")
@require_permission("inventory.view")
def product_ledger_breakdown(product_id):
    prod=one("SELECT * FROM products WHERE id=?",(product_id,))
    if not prod: return jsonify(error="Product not found."),404
    history=rows("SELECT * FROM inventory_transactions WHERE product_id=? ORDER BY timestamp ASC",(product_id,))
    opening=0
    if history:
        opening=int(history[0]["before_qty"])
    running=opening
    for h in history:
        running += int(h["delta_qty"])
    formula=[]
    if opening:
        formula.append({"item":"Opening balance","val":opening,"type":"base"})
    for h in history:
        formula.append({"item":h["transaction_type"],"val":int(h["delta_qty"]),"type":"movement"})
    formula.append({"item":"Current authoritative on-hand","val":int(prod["on_hand"]),"type":"result"})
    return jsonify({"product":prod,"formula":formula,"current_stock":int(prod["on_hand"]),"reconciled":running==int(prod["on_hand"]),"computed_from_transactions":running,"transactions":history})


# ==========================================
# 6-LEVEL DRILL-DOWN ANALYTICS
# ==========================================

@app.get("/api/drilldown")
@require_roles()
def get_drilldown():
    """
    Returns hierarchical Tree: Category -> Subcategory -> Product -> Variant.
    """
    prods = rows("""
        SELECT p.*, s.name as supplier_name
        FROM products p
        LEFT JOIN suppliers s ON p.supplier_id = s.id
    """)
    variants = rows("SELECT * FROM product_variants")

    var_map = {}
    for v in variants:
        var_map.setdefault(v["product_id"], []).append(v)

    tree = {}
    for p in prods:
        cat = p["category"]
        subcat = p["subcategory"]
        if cat not in tree:
            tree[cat] = {}
        if subcat not in tree[cat]:
            tree[cat][subcat] = []
        p_copy = dict(p)
        p_copy["variants"] = var_map.get(p["id"], [])
        tree[cat][subcat].append(p_copy)

    return jsonify(tree)
# ==========================================
# MULTI-WAREHOUSE, TRANSFERS & BINS
# ==========================================

@app.get("/api/warehouses")
@require_roles()
def get_warehouses():
    whs = rows("SELECT * FROM warehouses WHERE active=1")
    locations = rows("""
        SELECT psl.*, p.name as product_name, p.sku
        FROM product_stock_locations psl
        JOIN products p ON psl.product_id = p.id
    """)

    loc_map = {}
    for l in locations:
        loc_map.setdefault(l["warehouse_id"], []).append(l)

    for w in whs:
        w["inventory"] = loc_map.get(w["id"], [])
        w["total_units"] = sum(item["on_hand"] for item in w["inventory"])

    transfers = rows("""
        SELECT st.*, w1.name as from_warehouse_name, w2.name as to_warehouse_name,
               p.name as product_name, sti.quantity
        FROM stock_transfers st
        JOIN warehouses w1 ON st.from_warehouse_id = w1.id
        JOIN warehouses w2 ON st.to_warehouse_id = w2.id
        JOIN stock_transfer_items sti ON st.id = sti.transfer_id
        JOIN products p ON sti.product_id = p.id
        ORDER BY st.id DESC
    """)

    return jsonify(warehouses=whs, transfers=transfers)


@app.post("/api/transfers")
@require_roles("Owner", "General Manager")
def create_transfer():
    data = request.get_json(silent=True) or {}
    from_wh = int(data.get("from_warehouse_id"))
    to_wh = int(data.get("to_warehouse_id"))
    prod_id = int(data.get("product_id"))
    qty = int(data.get("quantity") or 0)
    notes = data.get("notes", "Inter-warehouse stock rebalance")
    user = current_user()

    if from_wh == to_wh or qty <= 0:
        return jsonify(error="Destination must differ from origin, and quantity must be positive."), 400

    trf_num = f"TRF-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"

    with db() as connection:
        # Check origin stock
        loc = connection.execute("SELECT * FROM product_stock_locations WHERE product_id=? AND warehouse_id=?", (prod_id, from_wh)).fetchone()
        if not loc or loc["on_hand"] < qty:
            return jsonify(error="Insufficient stock at origin warehouse location."), 400

        # Debit both the authoritative product aggregate and the selected source location.
        product = connection.execute("SELECT * FROM products WHERE id=?", (prod_id,)).fetchone()
        if not product or int(product["on_hand"])-int(product["reserved_qty"])-int(product["qc_hold_qty"])-int(product["damaged_qty"]) < qty:
            return jsonify(error="Insufficient available product stock for transfer."), 400
        before_product=int(product["on_hand"])
        before_location=int(loc["on_hand"])
        connection.execute("UPDATE products SET on_hand=on_hand-? WHERE id=?", (qty, prod_id))
        connection.execute("UPDATE product_stock_locations SET on_hand = on_hand - ? WHERE id=?", (qty, loc["id"]))

        cur = connection.execute("""
            INSERT INTO stock_transfers(transfer_number, from_warehouse_id, to_warehouse_id, status, created_by, dispatched_at, notes)
            VALUES(?,?,?,?,?,?,?)
        """, (trf_num, from_wh, to_wh, "In-Transit", user["name"], datetime.now().isoformat(), notes))
        trf_id = cur.lastrowid

        connection.execute("INSERT INTO stock_transfer_items(transfer_id, product_id, quantity) VALUES(?,?,?)", (trf_id, prod_id, qty))

        # Record audit ledger
        log_inventory_tx(connection, user, prod_id, "Transfer Out", before_product, -qty, notes,
                          source_warehouse_id=from_wh, source_bin=loc["bin_code"])

    return jsonify(message=f"Stock Transfer #{trf_num} initiated (Status: In-Transit).", transfer_number=trf_num)


@app.post("/api/transfers/<int:transfer_id>/receive")
@require_roles("Owner", "General Manager")
def receive_transfer(transfer_id):
    user = current_user()
    with db() as connection:
        trf = connection.execute("SELECT * FROM stock_transfers WHERE id=?", (transfer_id,)).fetchone()
        if not trf or trf["status"] != "In-Transit":
            return jsonify(error="Transfer not found or not in-transit."), 400

        items = connection.execute("SELECT * FROM stock_transfer_items WHERE transfer_id=?", (transfer_id,)).fetchall()
        to_wh = trf["to_warehouse_id"]

        for itm in items:
            p_id = itm["product_id"]
            qty = int(itm["quantity"])
            # Find or create location at destination
            loc = connection.execute("SELECT * FROM product_stock_locations WHERE product_id=? AND warehouse_id=?", (p_id, to_wh)).fetchone()
            product = connection.execute("SELECT * FROM products WHERE id=?", (p_id,)).fetchone()
            before_product = int(product["on_hand"])
            connection.execute("UPDATE products SET on_hand=on_hand+? WHERE id=?", (qty, p_id))
            if loc:
                connection.execute("UPDATE product_stock_locations SET on_hand = on_hand + ? WHERE id=?", (qty, loc["id"]))
                bin_c = loc["bin_code"]
                before = int(loc["on_hand"])
            else:
                bin_c = f"WH{to_wh}-AUTO-BIN"
                connection.execute("INSERT INTO product_stock_locations(product_id, warehouse_id, bin_code, on_hand) VALUES(?,?,?,?)",
                                   (p_id, to_wh, bin_c, qty))
                before = 0

            log_inventory_tx(connection, user, p_id, "Transfer In", before_product, qty,
                              f"Received {trf['transfer_number']}", dest_warehouse_id=to_wh, dest_bin=bin_c)

        connection.execute("UPDATE stock_transfers SET status='Received', received_at=? WHERE id=?", (datetime.now().isoformat(), transfer_id))

    return jsonify(message=f"Stock Transfer #{trf['transfer_number']} received at destination warehouse.")


# ==========================================
# BATCH TRACKING & FEFO ENGINE
# ==========================================

@app.get("/api/batches/fefo")
@require_roles()
def get_batches_fefo():
    """
    Returns batches prioritized by FEFO (First-Expired, First-Out).
    """
    sql = """
        SELECT b.*, p.name as product_name, p.sku, w.name as warehouse_name
        FROM product_batches b
        JOIN products p ON b.product_id = p.id
        JOIN warehouses w ON b.warehouse_id = w.id
        ORDER BY b.expiry_date ASC
    """
    return jsonify(rows(sql))


# ==========================================
# REVERSE LOGISTICS & RETURNS QC
# ==========================================

@app.get("/api/returns")
@require_roles()
def get_returns():
    ret_list = rows("SELECT * FROM returns ORDER BY id DESC")
    items = rows("""
        SELECT ri.*, p.name as product_name, p.sku
        FROM return_items ri
        JOIN products p ON ri.product_id = p.id
    """)
    itm_map = {}
    for i in items:
        itm_map.setdefault(i["return_id"], []).append(i)
    for r in ret_list:
        r["items"] = itm_map.get(r["id"], [])
    return jsonify(ret_list)


@app.post("/api/returns/<int:return_id>/inspect")
@require_roles("Owner", "General Manager", "Lower-Level Manager", "Handler")
def inspect_return(return_id):
    data = request.get_json(silent=True) or {}
    disposition = data.get("disposition") # 'Restock', 'Damaged Hold', 'Scrap'
    user = current_user()

    if disposition not in ("Restock", "Damaged Hold", "Scrap"):
        return jsonify(error="Disposition must be Restock, Damaged Hold, or Scrap."), 400

    with db() as connection:
        ret = connection.execute("SELECT * FROM returns WHERE id=?", (return_id,)).fetchone()
        if not ret:
            return jsonify(error="Return not found."), 404

        items = connection.execute("SELECT * FROM return_items WHERE return_id=?", (return_id,)).fetchall()
        for itm in items:
            p_id = itm["product_id"]
            qty = itm["quantity"]

            before = int(connection.execute("SELECT on_hand FROM products WHERE id=?", (p_id,)).fetchone()["on_hand"])
            if disposition == "Restock":
                connection.execute("UPDATE products SET on_hand = on_hand + ? WHERE id=?", (qty, p_id))
                action = "Return Restock"
            elif disposition == "Damaged Hold":
                action = "Return to Damaged Hold"
            else:
                action = "Scrap / Write-off"

            log_inventory_tx(connection, user, p_id, action, before, qty if disposition == "Restock" else 0,
                              f"QC Disposition: {disposition}")

        connection.execute("UPDATE returns SET status='Completed' WHERE id=?", (return_id,))
        connection.execute("UPDATE return_items SET disposition=?, inspected_by=? WHERE return_id=?", (disposition, user["name"], return_id))

    return jsonify(message=f"Return #{ret['return_number']} processed with disposition '{disposition}'.")


# ==========================================
# PARTIAL PO RECEIVING
# ==========================================

@app.post("/api/purchase-orders/<int:po_id>/partial-receive")
@require_roles("Owner", "General Manager", "Lower-Level Manager", "Handler")
def partial_receive_po(po_id):
    data = request.get_json(silent=True) or {}
    received_qty = int(data.get("received_quantity") or 0)
    user = current_user()

    if received_qty <= 0:
        return jsonify(error="Received quantity must be positive."), 400

    with db() as connection:
        po = connection.execute("SELECT * FROM purchase_orders WHERE id=?", (po_id,)).fetchone()
        if not po or po["status"] == "Received":
            return jsonify(error="PO not found or already fully completed."), 400

        item = connection.execute("SELECT * FROM purchase_order_items WHERE po_id=? LIMIT 1", (po_id,)).fetchone()
        if not item:
            return jsonify(error="PO line item not found."), 404

        new_received = item["received_quantity"] + received_qty
        new_pending = max(0, item["ordered_quantity"] - new_received)
        new_status = "Received" if new_pending == 0 else "Partially Received"

        connection.execute("""
            UPDATE purchase_order_items
            SET received_quantity=?, pending_quantity=?
            WHERE id=?
        """, (new_received, new_pending, item["id"]))

        connection.execute("UPDATE purchase_orders SET status=? WHERE id=?", (new_status, po_id))

        # Add to product stock
        connection.execute("UPDATE products SET on_hand = on_hand + ? WHERE id=?", (received_qty, item["product_id"]))
        apply_location_delta(connection, item["product_id"], int(received_qty))

        # Log audit
        before_qty = int(connection.execute("SELECT on_hand FROM products WHERE id=?", (item["product_id"],)).fetchone()["on_hand"]) - received_qty
        log_inventory_tx(connection, user, item["product_id"], "PO Receipt (Inbound)", before_qty, received_qty,
                          f"Delivery for {po['po_number']}", po_id=po_id)

    return jsonify(message=f"Received {received_qty} units for {po['po_number']}. Pending remaining: {new_pending} units. Status: {new_status}.")


# ==========================================
# PHYSICAL STOCKTAKE & RECONCILIATION
# ==========================================

@app.get("/api/stocktakes")
@require_roles()
def get_stocktakes():
    st_list = rows("""
        SELECT st.*, w.name as warehouse_name
        FROM stocktakes st
        JOIN warehouses w ON st.warehouse_id = w.id
        ORDER BY st.id DESC
    """)
    items = rows("""
        SELECT sti.*, p.name as product_name, p.sku
        FROM stocktake_items sti
        JOIN products p ON sti.product_id = p.id
    """)
    itm_map = {}
    for i in items:
        itm_map.setdefault(i["stocktake_id"], []).append(i)
    for s in st_list:
        s["items"] = itm_map.get(s["id"], [])
    return jsonify(st_list)


@app.post("/api/stocktakes/<int:stocktake_id>/reconcile")
@require_roles("Owner", "General Manager", "Lower-Level Manager")
def reconcile_stocktake(stocktake_id):
    user = current_user()
    with db() as connection:
        st = connection.execute("SELECT * FROM stocktakes WHERE id=?", (stocktake_id,)).fetchone()
        if not st or st["status"] == "Completed":
            return jsonify(error="Stocktake already completed or not found."), 400

        items = connection.execute("SELECT * FROM stocktake_items WHERE stocktake_id=?", (stocktake_id,)).fetchall()
        for itm in items:
            if itm["discrepancy"] != 0:
                # Adjust physical product stock
                connection.execute("UPDATE products SET on_hand = on_hand + ? WHERE id=?", (itm["discrepancy"], itm["product_id"]))
                # Audit ledger correction
                log_inventory_tx(connection, user, itm["product_id"], "Stocktake Adjustment",
                                  itm["system_qty"], itm["discrepancy"],
                                  "Physical Count Reconciliation", source_warehouse_id=st["warehouse_id"])

        connection.execute("UPDATE stocktakes SET status='Completed', approved_by=? WHERE id=?", (user["name"], stocktake_id))
        connection.execute("UPDATE stocktake_items SET reconciled=1 WHERE stocktake_id=?", (stocktake_id,))

    return jsonify(message=f"Stocktake #{st['stocktake_number']} reconciled. Discrepancies adjusted in audit ledger.")


# ==========================================
# GLOBAL POLY-SEARCH API
# ==========================================

@app.get("/api/search")
@require_roles()
def global_search():
    q = (request.args.get("q") or "").strip()
    if not q or len(q) < 2:
        return jsonify([])

    term = f"%{q}%"
    results = []

    # Search Products
    for p in rows("SELECT id, sku, name, category, on_hand, barcode FROM products WHERE name LIKE ? OR sku LIKE ? OR barcode LIKE ?", (term, term, term)):
        results.append({"type": "Product", "title": p["name"], "subtitle": f"SKU: {p['sku']} | Barcode: {p['barcode']}", "stock": p["on_hand"], "id": p["id"]})

    # Search POs
    for po in rows("SELECT id, po_number, status, total_cost FROM purchase_orders WHERE po_number LIKE ?", (term,)):
        results.append({"type": "Purchase Order", "title": po["po_number"], "subtitle": f"Status: {po['status']} | Total: â‚¹{po['total_cost']:,.2f}", "id": po["id"]})

    # Search Suppliers
    for sp in rows("SELECT id,name,category,contact_name FROM suppliers WHERE name LIKE ? OR category LIKE ? OR contact_name LIKE ?", (term, term, term)):
        results.append({"type":"Supplier","title":sp["name"],"subtitle":f"Category: {sp['category']} | Contact: {sp['contact_name']}","id":sp["id"]})

    # Search Orders
    for o in rows("SELECT id, order_number, customer_name, status FROM orders WHERE order_number LIKE ? OR customer_name LIKE ?", (term, term)):
        results.append({"type": "Customer Order", "title": o["order_number"], "subtitle": f"Customer: {o['customer_name']} | Status: {o['status']}", "id": o["id"]})

    # Search Warehouses
    for w in rows("SELECT id, name, city, code FROM warehouses WHERE name LIKE ? OR city LIKE ?", (term, term)):
        results.append({"type": "Warehouse", "title": w["name"], "subtitle": f"City: {w['city']} | Code: {w['code']}", "id": w["id"]})

    return jsonify(results[:10])


# ==========================================
# STANDARD CRUD & ML ENGINE FALLTHROUGH
# ==========================================

@app.get("/api/products")
@require_roles()
def get_products():
    sql = """
        SELECT p.*, s.name as supplier_name, s.lead_time_days as supplier_lead_time,
               (p.on_hand * p.price) as valuation,
               (p.on_hand * p.unit_cost) as inventory_cost,
               (p.on_hand - p.reserved_qty - p.qc_hold_qty - p.damaged_qty) as available_stock
        FROM products p
        LEFT JOIN suppliers s ON p.supplier_id = s.id
        ORDER BY p.id DESC
    """
    return jsonify(rows(sql))


@app.get("/api/suppliers")
@require_permission("supplier.view")
def get_suppliers():
    return jsonify(rows("""
        SELECT s.*,
               (SELECT COUNT(*) FROM products p WHERE p.supplier_id=s.id) AS product_count,
               (SELECT COALESCE(SUM(po.total_cost),0) FROM purchase_orders po WHERE po.supplier_id=s.id) AS purchase_value
        FROM suppliers s ORDER BY s.active DESC, s.name ASC
    """))


@app.get("/api/suppliers/<int:supplier_id>")
@require_permission("supplier.view")
def supplier_detail(supplier_id):
    supplier=one("SELECT * FROM suppliers WHERE id=?",(supplier_id,))
    if not supplier:return jsonify(error="Supplier not found."),404
    products=rows("""SELECT id,sku,name,category,status,unit_cost,price,on_hand,reorder_point,lead_time_days
                    FROM products WHERE supplier_id=? ORDER BY name""",(supplier_id,))
    pos=rows("""SELECT po.id,po.po_number,po.status,po.total_cost,po.expected_date,po.created_at,po.received_at
               FROM purchase_orders po WHERE po.supplier_id=? ORDER BY po.id DESC LIMIT 100""",(supplier_id,))
    summary=one("""SELECT COUNT(*) order_count,COALESCE(SUM(total_cost),0) purchase_value,
                        ROUND(AVG(lead_time_days),1) avg_lead_time
                 FROM purchase_orders po JOIN suppliers s ON s.id=po.supplier_id WHERE po.supplier_id=?""",(supplier_id,)) or {}
    return jsonify(supplier=supplier,products=products,purchase_orders=pos,summary=summary)


@app.post("/api/suppliers")
@require_permission("supplier.manage")
def create_supplier():
    data=request.get_json(silent=True) or {}
    name=str(data.get("name") or "").strip(); contact=str(data.get("contact_name") or "").strip()
    email=str(data.get("email") or "").strip(); phone=str(data.get("phone") or "").strip()
    category=str(data.get("category") or "General").strip()
    lead=int(data.get("lead_time_days") or 7)
    on_time=float(data.get("on_time_rate") or 95); defect=float(data.get("defect_rate") or 1)
    if not all([name,contact,email,phone]) or lead<=0:return jsonify(error="Supplier name, contact, email, phone and positive lead time are required."),400
    now=datetime.now().isoformat(); u=current_user()
    with db() as connection:
        cur=connection.execute("""INSERT INTO suppliers(name,contact_name,email,phone,category,lead_time_days,on_time_rate,defect_rate,created_at,active)
                                VALUES(?,?,?,?,?,?,?,?,?,1)""",(name,contact,email,phone,category,lead,on_time,defect,now))
        sid=cur.lastrowid
        connection.execute("INSERT INTO audit_logs(user_id,role,action,resource_type,resource_id,reason,created_at) VALUES(?,?,?,?,?,?,?)",(u["id"],u["role"],"supplier.create","supplier",str(sid),f"Created supplier {name}",now))
    return jsonify(id=sid,message="Supplier created."),201


@app.delete("/api/suppliers/<int:supplier_id>")
@require_permission("supplier.manage")
def archive_supplier(supplier_id):
    u=current_user(); now=datetime.now().isoformat()
    with db() as connection:
        srow=connection.execute("SELECT * FROM suppliers WHERE id=?",(supplier_id,)).fetchone()
        if not srow:return jsonify(error="Supplier not found."),404
        if not int(srow["active"] or 0):return jsonify(error="Supplier is already archived."),400
        connection.execute("UPDATE suppliers SET active=0, archived_at=? WHERE id=?",(now,supplier_id))
        connection.execute("INSERT INTO audit_logs(user_id,role,action,resource_type,resource_id,reason,created_at) VALUES(?,?,?,?,?,?,?)",(u["id"],u["role"],"supplier.archive","supplier",str(supplier_id),f"Archived supplier {srow['name']}; historical relationships preserved",now))
    return jsonify(message="Supplier archived. Historical purchase records remain available.")


@app.get("/api/purchase-orders")
@require_roles()
def get_purchase_orders():
    pos = rows("""
        SELECT po.*, s.name as supplier_name, s.lead_time_days
        FROM purchase_orders po
        JOIN suppliers s ON po.supplier_id = s.id
        ORDER BY po.id DESC
    """)
    items = rows("""
        SELECT poi.*, p.name as product_name, p.sku
        FROM purchase_order_items poi
        JOIN products p ON poi.product_id = p.id
    """)
    itm_map = {}
    for i in items:
        itm_map.setdefault(i["po_id"], []).append(i)
    for p in pos:
        p["items"] = itm_map.get(p["id"], [])
    return jsonify(pos)


@app.get("/api/orders")
@require_roles()
def get_orders():
    orders = rows("SELECT * FROM orders ORDER BY id DESC")
    items = rows("""
        SELECT oi.*, p.name as product_name, p.sku
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
    """)
    itm_map = {}
    for i in items:
        itm_map.setdefault(i["order_id"], []).append(i)
    for o in orders:
        o["items"] = itm_map.get(o["id"], [])
    return jsonify(orders)


@app.post("/api/orders")
@require_roles("Owner", "General Manager", "Lower-Level Manager")
def create_order():
    data=request.get_json(silent=True) or {}; cust_name=(data.get("customer_name") or "").strip(); cust_email=(data.get("customer_email") or "").strip(); items=data.get("items") or []
    if not cust_name or "@" not in cust_email or not items:return jsonify(error="Valid customer details and at least one item are required."),400
    user=current_user(); now=datetime.now().isoformat(); order_num=f"ORD-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
    with db() as connection:
        lines=[]
        for raw in items:
            try: pid=int(raw.get("product_id")); qty=int(raw.get("quantity"))
            except (TypeError,ValueError): return jsonify(error="Each order item needs a valid product and quantity."),400
            if qty<=0:return jsonify(error="Order quantities must be positive."),400
            prod=connection.execute("SELECT * FROM products WHERE id=? AND status='Active'",(pid,)).fetchone()
            if not prod:return jsonify(error=f"Product {pid} is not active or does not exist."),404
            available=int(prod["on_hand"])-int(prod["reserved_qty"])-int(prod["qc_hold_qty"])-int(prod["damaged_qty"])
            if available<qty:return jsonify(error=f"Insufficient available stock for '{prod['name']}'. Available: {max(0,available)}."),400
            loc=connection.execute("""SELECT * FROM product_stock_locations WHERE product_id=? AND (on_hand-reserved-qc_hold-damaged)>=?
                                      ORDER BY (on_hand-reserved-qc_hold-damaged) DESC,id LIMIT 1""",(pid,qty)).fetchone()
            lines.append((prod,qty,float(prod["price"]),float(prod["price"])*qty,loc))
        total=sum(x[3] for x in lines)
        cur=connection.execute("INSERT INTO orders(order_number,customer_name,customer_email,status,total_amount,created_at) VALUES(?,?,?,?,?,?)",(order_num,cust_name,cust_email,"Reserved",total,now)); oid=cur.lastrowid
        for prod,qty,price,sub,loc in lines:
            connection.execute("INSERT INTO order_items(order_id,product_id,quantity,unit_price,subtotal) VALUES(?,?,?,?,?)",(oid,prod["id"],qty,price,sub))
            wid=loc["warehouse_id"] if loc else None
            connection.execute("UPDATE products SET reserved_qty=reserved_qty+? WHERE id=?",(qty,prod["id"]))
            if loc:connection.execute("UPDATE product_stock_locations SET reserved=reserved+? WHERE id=?",(qty,loc["id"]))
            connection.execute("INSERT INTO reservations(order_id,product_id,warehouse_id,quantity,status,created_at) VALUES(?,?,?,?,?,?)",(oid,prod["id"],wid,qty,"Active",now))
            log_inventory_tx(connection,user,prod["id"],"Reservation",int(prod["on_hand"]),0,f"Order #{order_num} reserved; physical stock will deduct at picking",order_id=oid,source_warehouse_id=wid)
        connection.execute("INSERT INTO fulfillment_events(order_id,from_status,to_status,operator_id,note,created_at) VALUES(?,?,?,?,?,?)",(oid,"","Reserved",user["id"],"Inventory reserved; awaiting picking",now))
        connection.execute("INSERT INTO audit_logs(user_id,role,action,resource_type,resource_id,reason,created_at) VALUES(?,?,?,?,?,?,?)",(user["id"],user["role"],"order.reserve","order",str(oid),f"Order {order_num} reserved",now))
    return jsonify(message=f"Order #{order_num} created and inventory reserved.",order_id=oid,order_number=order_num,status="Reserved"),201


@app.get("/api/ai/forecast")
@require_roles()
def ai_forecast():
    prods = rows("SELECT * FROM products")
    forecasts = []
    for p in prods:
        history = rows("SELECT units_sold FROM sales_history WHERE product_id=? ORDER BY sale_date ASC", (p["id"],))
        sales = np.array([h["units_sold"] for h in history], dtype=float) if history else np.zeros(30, dtype=float)

        n = len(sales)
        x = np.arange(n).reshape(-1, 1)
        model = LinearRegression().fit(x, sales)
        pred = np.maximum(0, model.predict(np.arange(n, n + 30).reshape(-1, 1)))
        pred_30d = int(round(float(np.sum(pred))))

        d = float(np.mean(sales))
        sigma = float(np.std(sales))
        L = int(p["lead_time_days"] or 7)
        dynamic_ss = max(3, int(round(1.65 * sigma * math.sqrt(L))))
        dynamic_rop = int(round((d * L) + dynamic_ss))

        urgency = "CRITICAL" if p["on_hand"] <= max(3, int(dynamic_rop * 0.5)) else \
                  "REORDER_RECOMMENDED" if p["on_hand"] <= dynamic_rop else \
                  "OVERSTOCKED" if p["on_hand"] > dynamic_rop * 2.5 else "OPTIMAL"

        rec_order = max(10, int(round((dynamic_rop + pred_30d) - p["on_hand"]))) if p["on_hand"] <= dynamic_rop else 0

        forecasts.append({
            "product_id": p["id"],
            "forecast_method": "LinearRegression",
            "history_days": n,
            "forecast_confidence_note": "Projection, not a guaranteed outcome.",
            "sku": p["sku"],
            "name": p["name"],
            "category": p["category"],
            "current_stock": p["on_hand"],
            "unit_cost": p["unit_cost"],
            "avg_daily_demand": round(d, 2),
            "dynamic_safety_stock": dynamic_ss,
            "dynamic_reorder_point": dynamic_rop,
            "predicted_30d_demand": pred_30d,
            "urgency": urgency,
            "recommended_order_quantity": rec_order
        })

    return jsonify(forecasts=forecasts)


@app.get("/api/transfer-requests")
@require_permission("transfer.request")
def get_transfer_requests():
    return jsonify(rows("""SELECT r.*,p.name product_name,p.sku,w1.name source_warehouse,w2.name destination_warehouse
                          FROM stock_requests r JOIN products p ON p.id=r.product_id
                          LEFT JOIN warehouses w1 ON w1.id=r.source_warehouse_id
                          LEFT JOIN warehouses w2 ON w2.id=r.destination_warehouse_id
                          WHERE r.request_type='TRANSFER' ORDER BY r.id DESC"""))


@app.post("/api/transfer-requests")
@require_roles("Lower-Level Manager")
def create_transfer_request():
    user=current_user(); data=request.get_json(silent=True) or {}
    try:
        product_id=int(data.get("product_id")); source=int(data.get("source_warehouse_id")); dest=int(data.get("destination_warehouse_id")); qty=int(data.get("quantity"))
    except (TypeError,ValueError):return jsonify(error="Product, source, destination and quantity are required."),400
    reason=str(data.get("reason") or "Warehouse replenishment request").strip()
    if source==dest or qty<=0:return jsonify(error="Source and destination must differ and quantity must be positive."),400
    now=datetime.now().isoformat()
    with db() as connection:
        source_available=connection.execute("SELECT COALESCE(SUM(on_hand-reserved-qc_hold-damaged),0) n FROM product_stock_locations WHERE product_id=? AND warehouse_id=?",(product_id,source)).fetchone()[0]
        if int(source_available or 0)<qty:return jsonify(error="Not enough available stock at source warehouse."),400
        cur=connection.execute("""INSERT INTO stock_requests(product_id,request_type,quantity,reason,status,created_by,created_at,source_warehouse_id,destination_warehouse_id)
                                VALUES(?,?,?,?,?,?,?,?,?)""",(product_id,"TRANSFER",qty,reason,"Pending",user["name"],now,source,dest))
        rid=cur.lastrowid
        connection.execute("INSERT INTO request_history(request_id,actor_id,from_status,to_status,comment,created_at) VALUES(?,?,?,?,?,?)",(rid,user["id"],"Draft","Pending",reason,now))
    return jsonify(request_id=rid,message="Transfer request sent to the General Manager."),201


@app.post("/api/transfer-requests/<int:req_id>/approve")
@require_roles("Owner","General Manager")
def approve_transfer_request(req_id):
    user=current_user(); now=datetime.now().isoformat()
    with db() as connection:
        req=connection.execute("SELECT * FROM stock_requests WHERE id=? AND request_type='TRANSFER'",(req_id,)).fetchone()
        if not req:return jsonify(error="Transfer request not found."),404
        if req["status"]!="Pending":return jsonify(error="Transfer request is not pending."),400
        if req["created_by"]==user["name"]:return jsonify(error="You cannot approve your own transfer request."),403
        loc=connection.execute("SELECT * FROM product_stock_locations WHERE product_id=? AND warehouse_id=? ORDER BY id LIMIT 1",(req["product_id"],req["source_warehouse_id"])).fetchone()
        prod=connection.execute("SELECT * FROM products WHERE id=?",(req["product_id"],)).fetchone()
        if not loc or not prod:return jsonify(error="Transfer source data no longer exists."),409
        qty=int(req["quantity"]); avail=int(loc["on_hand"])-int(loc["reserved"] or 0)-int(loc["qc_hold"] or 0)-int(loc["damaged"] or 0)
        if avail<qty:return jsonify(error="Source stock changed; request needs re-validation."),409
        before=int(prod["on_hand"])
        connection.execute("UPDATE products SET on_hand=on_hand-? WHERE id=?",(qty,prod["id"]))
        connection.execute("UPDATE product_stock_locations SET on_hand=on_hand-? WHERE id=?",(qty,loc["id"]))
        trf=f"TRF-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
        cur=connection.execute("INSERT INTO stock_transfers(transfer_number,from_warehouse_id,to_warehouse_id,status,created_by,dispatched_at,notes) VALUES(?,?,?,?,?,?,?)",(trf,req["source_warehouse_id"],req["destination_warehouse_id"],"In-Transit",user["name"],now,req["reason"]))
        tid=cur.lastrowid
        connection.execute("INSERT INTO stock_transfer_items(transfer_id,product_id,quantity) VALUES(?,?,?)",(tid,prod["id"],qty))
        connection.execute("UPDATE stock_requests SET status='Approved',reviewed_by=?,transfer_id=? WHERE id=?",(user["name"],tid,req_id))
        connection.execute("INSERT INTO approvals(request_id,reviewer_id,decision,comment,previous_state,new_state,created_at) VALUES(?,?,?,?,?,?,?)",(req_id,user["id"],"Approved","Approved and dispatched","Pending","Approved",now))
        connection.execute("INSERT INTO request_history(request_id,actor_id,from_status,to_status,comment,created_at) VALUES(?,?,?,?,?,?)",(req_id,user["id"],"Pending","Approved",f"Transfer {trf} dispatched",now))
        log_inventory_tx(connection,user,prod["id"],"Transfer Out",before,-qty,f"Transfer request #{req_id} approved",source_warehouse_id=req["source_warehouse_id"],source_bin=loc["bin_code"],request_id=req_id)
    return jsonify(message="Transfer approved and dispatched.",transfer_id=tid,transfer_number=trf),200


@app.get("/api/requests")
@require_roles()
def get_requests():
    return jsonify(rows("""
        SELECT r.*, p.name as product_name, p.sku
        FROM stock_requests r
        JOIN products p ON r.product_id = p.id
        ORDER BY r.id DESC
    """))


@app.post("/api/requests/<int:req_id>/review")
@require_roles("Owner", "General Manager")
def review_request(req_id):
    data=request.get_json(silent=True) or {}
    decision=(data.get("status") or "").strip()
    comment=(data.get("comment") or "").strip()
    if decision not in ("Approved","Rejected","Escalated"):
        return jsonify(error="Status must be Approved, Rejected, or Escalated."),400
    user=current_user()
    with db() as connection:
        req=connection.execute("SELECT * FROM stock_requests WHERE id=?",(req_id,)).fetchone()
        if not req: return jsonify(error="Request not found."),404
        if req["created_by"] == user["name"]:
            return jsonify(error="A user cannot approve or reject their own request."),403
        previous=req["status"]
        connection.execute("UPDATE stock_requests SET status=?, reviewed_by=? WHERE id=?",(decision,user["name"],req_id))
        connection.execute("""
            INSERT INTO request_history(request_id,actor_id,from_status,to_status,comment,created_at)
            VALUES(?,?,?,?,?,?)
        """,(req_id,user["id"],previous,decision,comment,datetime.now().isoformat()))
        connection.execute("""
            INSERT INTO approvals(request_id,reviewer_id,decision,comment,previous_state,new_state,created_at)
            VALUES(?,?,?,?,?,?,?)
        """,(req_id,user["id"],decision,comment,previous,decision,datetime.now().isoformat()))
    return jsonify(message=f"Request {decision.lower()}.")


@app.get("/api/users")
@require_roles("Owner")
def get_users():
    return jsonify(rows("SELECT id, name, email, role, active FROM users ORDER BY role, name"))


@app.post("/api/users/<int:user_id>/toggle")
@require_roles("Owner")
def toggle_user(user_id):
    user=current_user(); now=datetime.now().isoformat()
    if int(user_id)==int(user["id"]): return jsonify(error="You cannot disable your own account."),403
    with db() as connection:
        target=connection.execute("SELECT id,name,active FROM users WHERE id=?",(user_id,)).fetchone()
        if not target:return jsonify(error="User not found."),404
        new_active=0 if target["active"] else 1
        connection.execute("UPDATE users SET active=? WHERE id=?",(new_active,user_id))
        connection.execute("INSERT INTO audit_logs(user_id,role,action,resource_type,resource_id,reason,created_at) VALUES(?,?,?,?,?,?,?)",(user["id"],user["role"],"user.access_toggle","user",str(user_id),f"Access changed to {'Active' if new_active else 'Disabled'} for {target['name']}",now))
    return jsonify(message=f"User access {'enabled' if new_active else 'disabled'}.",active=new_active)



# ==========================================
# EXTENDED PRODUCT CRUD & AUDIT LEDGER
# ==========================================

@app.post("/api/products")
@require_roles("Owner", "General Manager")
def create_product():
    data = request.get_json(silent=True) or {}
    sku = data.get("sku", "").strip()
    name = data.get("name", "").strip()
    category = data.get("category", "General").strip()
    subcategory = data.get("subcategory", "General").strip()
    price = float(data.get("price") or 0)
    unit_cost = float(data.get("unit_cost") or 0)
    on_hand = int(data.get("on_hand", data.get("stock", 0)))
    reorder_point = int(data.get("reorder_point") or 10)
    safety_stock = int(data.get("safety_stock") or 5)
    lead_time_days = int(data.get("lead_time_days") or 7)
    barcode = data.get("barcode") or f"890{secrets.token_hex(4).upper()}"
    image_url = data.get("image_url") or "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=240&auto=format&fit=crop&q=80"
    user = current_user()

    if not sku or not name or price <= 0:
        return jsonify(error="Valid SKU, name and price are required."), 400

    with db() as connection:
        existing = connection.execute("SELECT id FROM products WHERE sku=?", (sku,)).fetchone()
        if existing:
            return jsonify(error=f"A product with SKU '{sku}' already exists."), 400

        cur = connection.execute("""
            INSERT INTO products(sku, barcode, name, category, subcategory, price, unit_cost, on_hand, reorder_point, safety_stock, lead_time_days, image_url)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """, (sku, barcode, name, category, subcategory, price, unit_cost, on_hand, reorder_point, safety_stock, lead_time_days, image_url))
        prod_id = cur.lastrowid

        # Allocate to primary warehouse (Delhi)
        connection.execute("INSERT INTO product_stock_locations(product_id, warehouse_id, bin_code, on_hand) VALUES(?,?,?,?)",
                           (prod_id, 1, "DEL-R01-S01-B01", on_hand))

        import uuid
        connection.execute("""
            INSERT INTO inventory_transactions(transaction_id, timestamp, operator, product_id, source_warehouse_id, transaction_type, before_qty, delta_qty, after_qty, reason, user_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """, (str(uuid.uuid4()), datetime.now().isoformat(), user["name"], prod_id, 1, "Initial Stock Intake", 0, on_hand, on_hand, "Product Creation", user["id"]))

    return jsonify(message=f"Product '{name}' created.", id=prod_id), 201


@app.put("/api/products/<int:prod_id>")
@require_roles("Owner", "General Manager")
def update_product(prod_id):
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    price = float(data.get("price") or 0)
    unit_cost = float(data.get("unit_cost") or 0)
    reorder_point = int(data.get("reorder_point") or 10)
    safety_stock = int(data.get("safety_stock") or 5)

    with db() as connection:
        connection.execute("""
            UPDATE products
            SET name=?, price=?, unit_cost=?, reorder_point=?, safety_stock=?
            WHERE id=?
        """, (name, price, unit_cost, reorder_point, safety_stock, prod_id))

    return jsonify(message="Product updated successfully.")


@app.delete("/api/products/<int:prod_id>")
@require_roles("Owner", "General Manager")
def delete_product(prod_id):
    with db() as connection:
        cur = connection.execute("UPDATE products SET status='Archived' WHERE id=?", (prod_id,))
        if cur.rowcount == 0:
            return jsonify(error="Product not found."), 404
    return jsonify(message="Product archived.")


@app.get("/api/movements")
@require_roles()
def get_movements():
    return jsonify(rows("""
        SELECT m.*, p.name as product_name, p.sku
        FROM movements m
        JOIN products p ON m.product_id = p.id
        ORDER BY m.id DESC
    """))


@app.post("/api/movements")
@require_permission("inventory.adjust")
def create_movement():
    data = request.get_json(silent=True) or {}
    product_id = int(data.get("product_id"))
    kind = data.get("kind") # 'Stock in', 'Stock out', 'Damaged', 'Return'
    quantity = int(data.get("quantity") or 0)
    note = data.get("note", "").strip()
    user = current_user()

    if quantity <= 0:
        return jsonify(error="Quantity must be positive."), 400

    if kind not in ("Stock in", "Stock out", "Return", "Damaged"):
        return jsonify(error="Unsupported movement type."), 400

    with db() as connection:
        p = connection.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if not p:
            return jsonify(error="Product not found."), 404
        before_on_hand = int(p["on_hand"] or 0)
        if kind in ("Stock out", "Damaged") and before_on_hand < quantity:
            return jsonify(error="Cannot remove more units than physical on-hand stock."), 400

        if kind == "Damaged":
            delta = 0
            new_stock = before_on_hand
            connection.execute("UPDATE products SET damaged_qty=damaged_qty+? WHERE id=?", (quantity, product_id))
            apply_location_delta(connection, product_id, 0, damaged_delta=quantity)
        else:
            delta = quantity if kind in ("Stock in", "Return") else -quantity
            new_stock = before_on_hand + delta
            connection.execute("UPDATE products SET on_hand=? WHERE id=?", (new_stock, product_id))
            apply_location_delta(connection, product_id, delta)
        connection.execute("""
            INSERT INTO movements(product_id, kind, quantity, note, created_at, created_by)
            VALUES(?,?,?,?,?,?)
        """, (product_id, kind, quantity, note, datetime.now().isoformat(), user["name"]))

        log_inventory_tx(connection, user, product_id, f"Manual Movement ({kind})",
                          before_on_hand, delta, note or kind)

    return jsonify(message=f"Recorded {kind} of {quantity} units. New balance: {new_stock}.")


@app.post("/api/orders/<int:order_id>/cancel")
@require_roles("Owner", "General Manager", "Lower-Level Manager")
def cancel_order(order_id):
    user=current_user(); now=datetime.now().isoformat()
    with db() as connection:
        order=connection.execute("SELECT * FROM orders WHERE id=?",(order_id,)).fetchone()
        if not order:return jsonify(error="Order not found."),404
        if order["status"] in ("Cancelled","Shipped","Delivered"):return jsonify(error="This order cannot be cancelled in its current state."),400
        reservations=connection.execute("SELECT * FROM reservations WHERE order_id=? AND status='Active'",(order_id,)).fetchall()
        for r in reservations:
            connection.execute("UPDATE products SET reserved_qty=MAX(0,reserved_qty-?) WHERE id=?",(r["quantity"],r["product_id"]))
            if r["warehouse_id"]:connection.execute("UPDATE product_stock_locations SET reserved=MAX(0,reserved-?) WHERE product_id=? AND warehouse_id=?",(r["quantity"],r["product_id"],r["warehouse_id"]))
            connection.execute("UPDATE reservations SET status='Released',released_at=? WHERE id=?",(now,r["id"]))
        if order["status"] in ("Picking","Packed"):
            for itm in connection.execute("SELECT * FROM order_items WHERE order_id=?",(order_id,)).fetchall():
                prod=connection.execute("SELECT * FROM products WHERE id=?",(itm["product_id"],)).fetchone(); before=int(prod["on_hand"]); qty=int(itm["quantity"])
                connection.execute("UPDATE products SET on_hand=on_hand+? WHERE id=?",(qty,itm["product_id"])); apply_location_delta(connection,itm["product_id"],qty)
                log_inventory_tx(connection,user,itm["product_id"],"Cancellation Restock",before,qty,f"Cancelled order #{order['order_number']}",order_id=order_id)
        prev=order["status"]; connection.execute("UPDATE orders SET status='Cancelled' WHERE id=?",(order_id,))
        connection.execute("INSERT INTO fulfillment_events(order_id,from_status,to_status,operator_id,note,created_at) VALUES(?,?,?,?,?,?)",(order_id,prev,"Cancelled",user["id"],"Order cancellation completed",now))
        connection.execute("INSERT INTO audit_logs(user_id,role,action,resource_type,resource_id,reason,created_at) VALUES(?,?,?,?,?,?,?)",(user["id"],user["role"],"order.cancel","order",str(order_id),f"Order moved from {prev} to Cancelled",now))
    return jsonify(message=f"Order #{order['order_number']} cancelled.")


@app.post("/api/purchase-orders")
@require_roles("Owner", "General Manager")
def create_purchase_order():
    data = request.get_json(silent=True) or {}
    supplier_id = int(data.get("supplier_id"))
    items = data.get("items", [])
    expected_days = int(data.get("expected_days") or 7)
    user = current_user()

    if not items:
        return jsonify(error="At least one product required."), 400

    po_num = f"PO-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
    exp_date = (date.today() + timedelta(days=expected_days)).isoformat()
    total_cost = 0.0

    with db() as connection:
        line_items = []
        for itm in items:
            p_id = int(itm["product_id"])
            qty = int(itm["quantity"])
            p = connection.execute("SELECT * FROM products WHERE id=?", (p_id,)).fetchone()
            cost = float(p["unit_cost"]) if p else 100.0
            total_cost += cost * qty
            line_items.append((p_id, qty, cost))

        cur = connection.execute("""
            INSERT INTO purchase_orders(po_number, supplier_id, status, total_cost, expected_date, created_by, created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (po_num, supplier_id, "Ordered", total_cost, exp_date, user["name"], datetime.now().isoformat()))
        po_id = cur.lastrowid

        for p_id, qty, cost in line_items:
            connection.execute("""
                INSERT INTO purchase_order_items(po_id, product_id, ordered_quantity, received_quantity, pending_quantity, unit_cost)
                VALUES(?,?,?,?,?,?)
            """, (po_id, p_id, qty, 0, qty, cost))

    return jsonify(message=f"Purchase Order #{po_num} issued to supplier.", po_id=po_id, po_number=po_num), 201


@app.post("/api/purchase-orders/<int:po_id>/receive")
@require_roles("Owner", "General Manager", "Lower-Level Manager")
def receive_full_purchase_order(po_id):
    user = current_user()
    with db() as connection:
        po = connection.execute("SELECT * FROM purchase_orders WHERE id=?", (po_id,)).fetchone()
        if not po or po["status"] == "Received":
            return jsonify(error="PO not found or already received."), 400

        items = connection.execute("SELECT * FROM purchase_order_items WHERE po_id=?", (po_id,)).fetchall()
        for itm in items:
            qty_to_add = itm["pending_quantity"]
            if qty_to_add > 0:
                connection.execute("UPDATE products SET on_hand = on_hand + ? WHERE id=?", (qty_to_add, itm["product_id"]))
                apply_location_delta(connection, itm["product_id"], int(qty_to_add))
                before_qty = int(connection.execute("SELECT on_hand FROM products WHERE id=?", (itm["product_id"],)).fetchone()["on_hand"]) - qty_to_add
                log_inventory_tx(connection, user, itm["product_id"], "PO Receipt (Full)", before_qty, qty_to_add,
                                  f"Full fulfillment for {po['po_number']}", po_id=po_id)

            connection.execute("""
                UPDATE purchase_order_items
                SET received_quantity = ordered_quantity, pending_quantity = 0
                WHERE id=?
            """, (itm["id"],))

        connection.execute("UPDATE purchase_orders SET status='Received', received_at=? WHERE id=?", (datetime.now().isoformat(), po_id))

    return jsonify(message=f"Purchase Order #{po['po_number']} fully received and inventory replenished.")


@app.post("/api/requests")
@require_roles("Owner", "General Manager", "Lower-Level Manager", "Handler")
def create_stock_request():
    data = request.get_json(silent=True) or {}
    product_id = int(data.get("product_id"))
    request_type = data.get("request_type", "Restock")
    quantity = int(data.get("quantity") or 0)
    reason = data.get("reason", "").strip()
    user = current_user()

    if quantity <= 0 or not reason:
        return jsonify(error="Quantity and reason required."), 400

    with db() as connection:
        connection.execute("""
            INSERT INTO stock_requests(product_id, request_type, quantity, reason, status, created_by, created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (product_id, request_type, quantity, reason, "Pending", user["name"], datetime.now().isoformat()))

    return jsonify(message="Stock request submitted for managerial review."), 201


@app.get("/api/ai/dead-stock")
@require_roles()
def get_dead_stock():
    sql = """
        SELECT p.*,
               COALESCE((SELECT SUM(sh.units_sold) FROM sales_history sh WHERE sh.product_id=p.id AND sh.sale_date>=date('now','-30 days')),0) AS units_30d,
               (p.on_hand * p.unit_cost) as locked_capital,
               (SELECT MAX(sh.sale_date) FROM sales_history sh WHERE sh.product_id=p.id AND sh.units_sold>0) AS last_sale_date
        FROM products p
        ORDER BY locked_capital DESC
    """
    items=[]
    for item in rows(sql):
        d=dict(item); d["days_since_sale"] = None
        if d.get("last_sale_date"):
            try: d["days_since_sale"]=(date.today()-date.fromisoformat(d["last_sale_date"])).days
            except ValueError: pass
        if int(d.get("on_hand") or 0)>40 and (d.get("days_since_sale") is None or d["days_since_sale"]>90): items.append(d)
    return jsonify(items)


@app.post("/api/ai/auto-po")
@require_roles("Owner", "General Manager")
def ai_auto_po():
    data = request.get_json(silent=True) or {}
    product_id = int(data.get("product_id"))
    quantity = int(data.get("quantity") or 0)
    user = current_user()

    if quantity <= 0:
        return jsonify(error="Quantity must be positive."), 400

    prod = one("SELECT * FROM products WHERE id=?", (product_id,))
    if not prod:
        return jsonify(error="Product not found."), 404

    supp_id = prod["supplier_id"] or 1
    po_num = f"PO-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
    cost = float(prod["unit_cost"]) * quantity
    exp_date = (date.today() + timedelta(days=int(prod["lead_time_days"] or 7))).isoformat()

    with db() as connection:
        cur = connection.execute("""
            INSERT INTO purchase_orders(po_number, supplier_id, status, total_cost, expected_date, created_by, created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (po_num, supp_id, "Ordered", cost, exp_date, user["name"], datetime.now().isoformat()))
        po_id = cur.lastrowid

        connection.execute("""
            INSERT INTO purchase_order_items(po_id, product_id, ordered_quantity, received_quantity, pending_quantity, unit_cost)
            VALUES(?,?,?,?,?,?)
        """, (po_id, product_id, quantity, 0, quantity, float(prod["unit_cost"])))

    return jsonify(message=f"AI Auto-PO #{po_num} created for '{prod['name']}'.", po_number=po_num, po_id=po_id)


@app.get("/api/audit-logs")
@require_roles()
def get_audit_logs():
    sql = """
        SELECT al.*, p.name as product_name, p.sku
        FROM inventory_transactions al
        LEFT JOIN products p ON al.product_id = p.id
        ORDER BY al.timestamp DESC
        LIMIT 100
    """
    return jsonify(rows(sql))



# ==========================================
# LIVE DATA / DEEP WORKFLOW API
# ==========================================

@app.get("/api/analytics/overview")
@require_permission("analytics.view")
def analytics_overview():
    start = request.args.get("from") or "2022-01-01"
    end = request.args.get("to") or date.today().isoformat()
    sales = one("""
        SELECT COALESCE(SUM(units_sold),0) units, COUNT(*) rows
        FROM sales_history WHERE sale_date BETWEEN ? AND ?
    """, (start, end))
    orders = one("""
        SELECT COUNT(*) orders, COALESCE(SUM(total_amount),0) revenue,
               COALESCE(AVG(total_amount),0) aov
        FROM orders WHERE date(created_at) BETWEEN ? AND ? AND status <> 'Cancelled'
    """, (start, end))
    cogs = one("""
        SELECT COALESCE(SUM(oi.quantity*p.unit_cost),0) cogs
        FROM orders o JOIN order_items oi ON oi.order_id=o.id
        JOIN products p ON p.id=oi.product_id
        WHERE date(o.created_at) BETWEEN ? AND ? AND o.status <> 'Cancelled'
    """, (start, end))
    monthly = rows("""
        SELECT substr(sale_date,1,7) ym, SUM(units_sold) units
        FROM sales_history WHERE sale_date BETWEEN ? AND ?
        GROUP BY ym ORDER BY ym
    """, (start, end))
    categories = rows("""
        SELECT category, COUNT(*) products, SUM(on_hand) on_hand,
               SUM(on_hand*unit_cost) inventory_value
        FROM products GROUP BY category ORDER BY inventory_value DESC
    """)
    warehouses = rows("""
        SELECT w.id,w.code,w.name,w.city,
               COALESCE(SUM(l.on_hand),0) on_hand,
               COALESCE(SUM(l.reserved),0) reserved,
               COALESCE(SUM(l.qc_hold),0) qc_hold,
               COALESCE(SUM(l.damaged),0) damaged
        FROM warehouses w LEFT JOIN product_stock_locations l ON l.warehouse_id=w.id
        GROUP BY w.id ORDER BY on_hand DESC
    """)
    supplier = rows("""
        SELECT s.id,s.name,COUNT(po.id) order_count,COALESCE(SUM(po.total_cost),0) purchase_value,
               s.lead_time_days,s.on_time_rate,s.defect_rate
        FROM suppliers s LEFT JOIN purchase_orders po ON po.supplier_id=s.id
        GROUP BY s.id ORDER BY purchase_value DESC
    """)
    return jsonify({
        "period":{"from":start,"to":end},
        "sales":{"units":int(sales["units"] or 0),"records":int(sales["rows"] or 0)},
        "orders":{"count":int(orders["orders"] or 0),"revenue":float(orders["revenue"] or 0),"aov":round(float(orders["aov"] or 0),2)},
        "profit":{"cogs":float(cogs["cogs"] or 0),"gross_profit":round(float(orders["revenue"] or 0)-float(cogs["cogs"] or 0),2)},
        "monthly":monthly,"categories":categories,"warehouses":warehouses,"suppliers":supplier
    })


@app.get("/api/products/<int:prod_id>")
@require_permission("product.view")
def product_detail(prod_id):
    product = one("""
        SELECT p.*, s.name supplier_name FROM products p
        LEFT JOIN suppliers s ON s.id=p.supplier_id WHERE p.id=?
    """, (prod_id,))
    if not product: return jsonify(error="Product not found."), 404
    locations = rows("""
        SELECT l.*, w.name warehouse_name FROM product_stock_locations l
        JOIN warehouses w ON w.id=l.warehouse_id WHERE l.product_id=? ORDER BY w.name,l.bin_code
    """, (prod_id,))
    batches = rows("SELECT * FROM product_batches WHERE product_id=? ORDER BY expiry_date", (prod_id,))
    variants = rows("SELECT * FROM product_variants WHERE product_id=? ORDER BY id", (prod_id,))
    recent = rows("""
        SELECT * FROM inventory_transactions WHERE product_id=? ORDER BY timestamp DESC LIMIT 100
    """, (prod_id,))
    history = rows("""
        SELECT sale_date,units_sold FROM sales_history WHERE product_id=? ORDER BY sale_date DESC LIMIT 365
    """, (prod_id,))
    available = max(0, int(product["on_hand"])-int(product["reserved_qty"])-int(product["qc_hold_qty"])-int(product["damaged_qty"]))
    return jsonify({"product":dict(product),"available":available,"locations":locations,"batches":batches,"variants":variants,"transactions":recent,"sales_history":history})


@app.get("/api/inventory/locations")
@require_permission("inventory.view")
def inventory_locations():
    return jsonify(rows("""
        SELECT l.id,l.product_id,p.sku,p.name,l.warehouse_id,w.name warehouse_name,l.bin_code,
               l.on_hand,l.reserved,l.qc_hold,l.damaged,
               (l.on_hand-l.reserved-l.qc_hold-l.damaged) available
        FROM product_stock_locations l
        JOIN products p ON p.id=l.product_id JOIN warehouses w ON w.id=l.warehouse_id
        ORDER BY w.name,p.name,l.bin_code
    """))


@app.post("/api/purchase-orders/<int:po_id>/receive-to-qc")
@require_permission("inventory.receive")
def receive_to_qc(po_id):
    user = current_user(); data = request.get_json(silent=True) or {}
    item_id = data.get("item_id")
    requested_qty = int(data.get("quantity") or 0)
    with db() as connection:
        po = connection.execute("SELECT * FROM purchase_orders WHERE id=?", (po_id,)).fetchone()
        if not po: return jsonify(error="Purchase order not found."),404
        if item_id:
            items = connection.execute("SELECT * FROM purchase_order_items WHERE id=? AND po_id=?", (int(item_id),po_id)).fetchall()
        else:
            items = connection.execute("SELECT * FROM purchase_order_items WHERE po_id=? AND pending_quantity>0", (po_id,)).fetchall()
        if not items: return jsonify(error="No pending PO items."),400
        received=[]
        for item in items:
            qty=min(int(item["pending_quantity"]), requested_qty or int(item["pending_quantity"]))
            if qty<=0: continue
            p=connection.execute("SELECT * FROM products WHERE id=?",(item["product_id"],)).fetchone()
            before=int(p["on_hand"])
            connection.execute("UPDATE products SET on_hand=on_hand+?, qc_hold_qty=qc_hold_qty+? WHERE id=?",(qty,qty,p["id"]))
            apply_location_delta(connection, p["id"], qty, qc_delta=qty)
            connection.execute("UPDATE purchase_order_items SET received_quantity=received_quantity+?, pending_quantity=pending_quantity-? WHERE id=?",(qty,qty,item["id"]))
            connection.execute("INSERT INTO qc_inspections(purchase_order_id,product_id,quantity,status,inspector_id,created_at) VALUES(?,?,?,?,?,?)",(po_id,p["id"],qty,"Pending",user["id"],datetime.now().isoformat()))
            log_inventory_tx(connection,user,p["id"],"Purchase Receipt - QC Hold",before,qty,f"PO {po['po_number']} received to QC",po_id=po_id)
            received.append({"product_id":p["id"],"quantity":qty})
        pending=connection.execute("SELECT COALESCE(SUM(pending_quantity),0) FROM purchase_order_items WHERE po_id=?",(po_id,)).fetchone()[0]
        status="Partially Received" if pending else "Fully Received"
        connection.execute("UPDATE purchase_orders SET status=?,received_at=? WHERE id=?",(status,datetime.now().isoformat(),po_id))
    return jsonify(message="Receipt recorded in QC hold.",status=status,received=received)


@app.get("/api/qc/pending")
@require_permission("return.inspect")
def pending_qc():
    return jsonify(rows("""
        SELECT q.*, p.name product_name,p.sku,po.po_number
        FROM qc_inspections q JOIN products p ON p.id=q.product_id
        LEFT JOIN purchase_orders po ON po.id=q.purchase_order_id
        WHERE q.status='Pending' ORDER BY q.created_at
    """))


@app.post("/api/qc/<int:qcid>/decision")
@require_permission("return.inspect")
def qc_decision(qcid):
    user=current_user(); data=request.get_json(silent=True) or {}
    decision=data.get("decision")
    if decision not in ("Accepted","Rejected","Damaged"): return jsonify(error="Decision must be Accepted, Rejected, or Damaged."),400
    with db() as connection:
        q=connection.execute("SELECT * FROM qc_inspections WHERE id=?",(qcid,)).fetchone()
        if not q or q["status"]!="Pending": return jsonify(error="QC inspection not pending."),400
        product=connection.execute("SELECT * FROM products WHERE id=?",(q["product_id"],)).fetchone()
        qty=int(q["quantity"]); before=int(product["on_hand"])
        if decision=="Accepted":
            connection.execute("UPDATE products SET qc_hold_qty=MAX(0,qc_hold_qty-?) WHERE id=?",(qty,q["product_id"]))
            apply_location_delta(connection, q["product_id"], 0, qc_delta=-qty)
            accepted,damaged,rejected=qty,0,0
        elif decision=="Damaged":
            connection.execute("UPDATE products SET qc_hold_qty=MAX(0,qc_hold_qty-?), damaged_qty=damaged_qty+? WHERE id=?",(qty,qty,q["product_id"]))
            apply_location_delta(connection, q["product_id"], 0, qc_delta=-qty, damaged_delta=qty)
            accepted,damaged,rejected=0,qty,0
        else:
            connection.execute("UPDATE products SET on_hand=MAX(0,on_hand-?), qc_hold_qty=MAX(0,qc_hold_qty-?) WHERE id=?",(qty,qty,q["product_id"]))
            apply_location_delta(connection, q["product_id"], -qty, qc_delta=-qty)
            accepted,damaged,rejected=0,0,qty
        connection.execute("UPDATE qc_inspections SET status=?,accepted_quantity=?,rejected_quantity=?,damaged_quantity=?,reason=?,inspector_id=? WHERE id=?",(decision,accepted,rejected,damaged,data.get("reason",""),user["id"],qcid))
        if decision=="Rejected": delta=-qty
        else: delta=0
        if delta:
            log_inventory_tx(connection,user,q["product_id"],"QC Rejection",before,delta,"Rejected receipt quantity")
        else:
            log_inventory_tx(connection,user,q["product_id"],f"QC {decision}",before,0,data.get("reason","") or decision)
    return jsonify(message=f"QC decision recorded: {decision}.")


@app.post("/api/orders/<int:order_id>/status")
@require_permission("order.fulfill")
def order_status(order_id):
    target=(request.get_json(silent=True) or {}).get("status"); transitions={"Reserved":"Picking","Picking":"Packed","Packed":"Shipped","Shipped":"Delivered"}; user=current_user(); now=datetime.now().isoformat()
    with db() as connection:
        order=connection.execute("SELECT * FROM orders WHERE id=?",(order_id,)).fetchone()
        if not order:return jsonify(error="Order not found."),404
        if transitions.get(order["status"])!=target:return jsonify(error=f"Invalid order transition from {order['status']} to {target}."),400
        if target=="Picking":
            reservations=connection.execute("SELECT * FROM reservations WHERE order_id=? AND status='Active'",(order_id,)).fetchall()
            if not reservations:return jsonify(error="Order has no active reservations."),409
            for r in reservations:
                prod=connection.execute("SELECT * FROM products WHERE id=?",(r["product_id"],)).fetchone(); qty=int(r["quantity"])
                available=int(prod["on_hand"])-int(prod["reserved_qty"])-int(prod["qc_hold_qty"])-int(prod["damaged_qty"])
                if available<qty:return jsonify(error=f"Picking blocked for {prod['name']}: available stock changed since reservation."),409
                before=int(prod["on_hand"]); connection.execute("UPDATE products SET on_hand=on_hand-?, reserved_qty=MAX(0,reserved_qty-?) WHERE id=?",(qty,qty,prod["id"]))
                if r["warehouse_id"]:connection.execute("UPDATE product_stock_locations SET on_hand=on_hand-?,reserved=MAX(0,reserved-?) WHERE product_id=? AND warehouse_id=?",(qty,qty,prod["id"],r["warehouse_id"]))
                else:apply_location_delta(connection,prod["id"],-qty)
                connection.execute("UPDATE reservations SET status='Fulfilled',released_at=? WHERE id=?",(now,r["id"]))
                log_inventory_tx(connection,user,prod["id"],"Sale",before,-qty,f"Order #{order['order_number']} picked",order_id=order_id,source_warehouse_id=r["warehouse_id"])
        prev=order["status"]; connection.execute("UPDATE orders SET status=? WHERE id=?",(target,order_id))
        connection.execute("INSERT INTO fulfillment_events(order_id,from_status,to_status,operator_id,note,created_at) VALUES(?,?,?,?,?,?)",(order_id,prev,target,user["id"],f"Order moved from {prev} to {target}",now))
        connection.execute("INSERT INTO audit_logs(user_id,role,action,resource_type,resource_id,reason,created_at) VALUES(?,?,?,?,?,?,?)",(user["id"],user["role"],f"order.status.{target.lower()}","order",str(order_id),f"Order moved from {prev} to {target}",now))
    return jsonify(message=f"Order {order['order_number']} moved to {target}.",status=target)


@app.get("/api/notifications")
@require_roles()
def notifications():
    u=current_user()
    return jsonify(rows("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50",(u["id"],)))


@app.post("/api/notifications/<int:nid>/read")
@require_roles()
def notification_read(nid):
    u=current_user()
    with db() as connection:
        connection.execute("UPDATE notifications SET read_at=? WHERE id=? AND user_id=?",(datetime.now().isoformat(),nid,u["id"]))
    return jsonify(message="Notification marked as read.")


@app.get("/api/reports/inventory")
@require_permission("reports.view")
def inventory_report():
    return jsonify(rows("""
        SELECT p.id,p.sku,p.name,p.category,p.subcategory,p.status,p.on_hand,p.reserved_qty,p.qc_hold_qty,p.damaged_qty,
               (p.on_hand-p.reserved_qty-p.qc_hold_qty-p.damaged_qty) available,
               p.unit_cost,(p.on_hand*p.unit_cost) inventory_value,p.reorder_point,p.safety_stock,p.monthly_sales
        FROM products p ORDER BY inventory_value DESC
    """))


@app.get("/api/reports/sales")
@require_permission("reports.view")
def sales_report():
    return jsonify(rows("""
        SELECT substr(sale_date,1,7) month,SUM(units_sold) units FROM sales_history
        GROUP BY month ORDER BY month
    """))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)

