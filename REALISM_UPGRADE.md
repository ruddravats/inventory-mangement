# StockSphere realism upgrade

This build uses the 5-year SQLite dataset as the live application database.

## Current operational state
- 12 live customer orders across Reserved, Picking, Packed and Shipped.
- 8 live inbound purchase orders, including partial receipts.
- Active inventory reservations tied to open orders.
- Current approval/request exceptions for restock, adjustment, transfer, expiry and damage workflows.
- Live notifications for inventory risk, inbound supply and approvals.

## Business-rule upgrades
- Order creation reserves inventory instead of immediately consuming physical stock.
- Physical inventory is consumed when an order enters Picking.
- Cancellation releases reservations; picked/packed orders can restock physical units.
- Handler cannot perform manual add/remove inventory adjustments.
- Handler receives inbound goods into QC hold; management performs QC decisions.
- Full PO receiving is manager-only.
- Product/location inventory remains reconciled after transfers and stock operations.
- User access changes and security operations are audited.
- Product archive preserves historical transactions.

## Source of truth
The product aggregate and location balances are reconciled against inventory transactions. Available stock is derived from on-hand less reserved, QC-held and damaged/blocked quantities.
