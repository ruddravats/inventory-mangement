# StockSphere — 5-Year Integrated Inventory Platform

StockSphere is a Flask + SQLite inventory and operations platform wired to a single authoritative database. The bundled database contains the 5-year demonstration dataset and is used directly by the web application.

## Run

```powershell
cd StockSphere
py -m pip install -r requirements.txt
py app.py
```

Open `http://127.0.0.1:5000`.

## Demo users

Password for all demo users: `demo123`

| Role | Email |
|---|---|
| Owner | owner@stocksphere.demo |
| General Manager | manager@stocksphere.demo |
| Lower-Level Manager | ops@stocksphere.demo |
| Handler | handler@stocksphere.demo |

## Live 5-year data

The application uses:

`dataset_5yr/stocksphere_5yr.db`

The database contains 5-year sales/inventory history plus products, suppliers, warehouses, orders, purchase orders, returns, stocktakes, requests, transfers, audit records, sessions and security events.

## Role enforcement

Authorization is enforced on the backend, not only in the browser.

### Owner
Full access, administration, audit, analytics, users, overrides and security.

### General Manager
Product/catalogue management, purchasing, inventory controls, analytics and operational workflows.

### Lower-Level Manager
Requests/approvals, receiving/QC, stocktake review, returns, transfers and controlled inventory adjustment.

### Handler
Floor execution only: view/search inventory, receive approved POs into QC hold, process eligible return inspections, count stock, advance assigned order workflow and create requests.

**Handlers cannot call the manual inventory adjustment endpoint.** Add/Remove/Damaged stock from the manual adjustment screen requires the `inventory.adjust` permission, which is not granted to Handler. Handler replenishment or discrepancy actions must use the request/receiving workflow.

## Inventory rules

- Product `on_hand` is the authoritative physical quantity.
- `available = on_hand - reserved - qc_hold - damaged`.
- Every stock-changing operation writes an inventory transaction.
- `before + delta = after` is enforced by the transaction logic.
- Product history is archived rather than deleted.
- Historical data is retained; the same schema supports future years without creating separate yearly tables.

## Important workflows

- Customer order → inventory deduction → transaction log
- Purchase order → receiving → inventory transaction
- Handler receipt → QC hold → manager QC decision
- Warehouse transfer → dispatch → receipt
- Return → inspection → restock/damage/scrap
- Stocktake → discrepancy → approved reconciliation
- Request → review → approval/rejection → history
- Forecast → reorder recommendation → Auto-PO

## Dataset validation

The bundled dataset was checked for duplicate SKU/serial values, negative inventory, negative availability and product-to-location inventory mismatches.
