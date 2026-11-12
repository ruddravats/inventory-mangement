# StockSphere Realism Upgrade v2

## Product drill-down
- Clicking a product opens a dedicated product intelligence page.
- Shows live stock states, warehouse/bin distribution, batches, variants, transaction timeline and five-year sales history.
- Supplier is a clickable relationship into the supplier detail page.

## Dashboard drill-down
- KPI cards open live detailed records.
- Sales chart now uses a 12-month sales history with separate sales-value/gross-profit and units views.
- Inventory health, inbound purchase orders, low-stock and purchase-order details are drillable.
- Supplier network summary is directly linked to the supplier workspace.

## Supplier governance
- Owner: view/add/archive suppliers.
- General Manager: view supplier contact, performance, supplied products and PO history; no add/archive controls.
- Supplier archive is soft-delete; historical purchasing relationships remain intact.

## Transfer governance
- Lower-Level Manager: may submit transfer requests only.
- General Manager / Owner: may approve and dispatch a requested transfer.
- Inventory does not move when a Lower-Level Manager submits a request.
- Approval is recorded in request history, approvals and inventory transactions.
- Source stock is revalidated at approval time.
- Receipt is a separate management operation.

## Data quality
- Five-year sales history is continuous through 2026-08-27 with realistic month-to-month demand variation.
- Dashboard trend values are calculated from stored sales history and product pricing/cost data, not presentation constants.
- Root `stocksphere.db` is the live application database and is synchronized with the packaged five-year dataset.
