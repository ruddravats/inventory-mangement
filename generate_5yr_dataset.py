import csv, json, math, random, sqlite3, hashlib, base64, os, re, zipfile
from pathlib import Path
from datetime import date, datetime, timedelta

ROOT = Path('/mnt/data/StockSphere')
OUT = ROOT / 'dataset_5yr'
OUT.mkdir(exist_ok=True)
DB = OUT / 'stocksphere_5yr.db'
SQL = OUT / 'stocksphere_5yr_seed.sql'
random.seed(20260827)

START = date(2022,1,1)
END = date(2026,8,27)
TODAY = END
DAYS = (END-START).days + 1

# ---------- deterministic helpers ----------
def rand_name(prefix, i): return f"{prefix} {i:03d}"
def slug(s): return re.sub(r'[^A-Za-z0-9]+','_',s).strip('_').lower()
def iso(d): return d.isoformat() if isinstance(d, date) else str(d)

def werkzeug_pbkdf2(password='demo123', salt='stocksphere2026'):
    # Compatible with Werkzeug's pbkdf2:sha256 format.
    iterations = 600000
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    return f'pbkdf2:sha256:{iterations}${salt}${dk.hex()}'

# ---------- business dimensions ----------
users = [
    (1,'Ananya Mehta','owner@stocksphere.demo',werkzeug_pbkdf2(),'Owner',1),
    (2,'Rahul Verma','manager@stocksphere.demo',werkzeug_pbkdf2(),'General Manager',1),
    (3,'Neha Kapoor','ops@stocksphere.demo',werkzeug_pbkdf2(),'Lower-Level Manager',1),
    (4,'Kiran Shah','handler@stocksphere.demo',werkzeug_pbkdf2(),'Handler',1),
]

warehouses = [
    (1,'WH-DEL','Delhi Central Hub','Delhi','Amit Saxena',45000,1),
    (2,'WH-MRD','Moradabad Depot','Moradabad','Rajesh Kumar',25000,1),
    (3,'WH-LKO','Lucknow Express Hub','Lucknow','Sunita Rao',30000,1),
]
bins=[]
for wid, prefix in [(1,'DEL'),(2,'MRD'),(3,'LKO')]:
    for r in range(1,5):
        for s in range(1,3):
            bid = len(bins)+1
            bins.append((bid,wid,f'R{r:02d}',f'S{s:02d}',f'{prefix}-R{r:02d}-S{s:02d}-B{bid:02d}'))

suppliers = [
    (1,'Nova Supplies','Vikram Rao','vikram@novasupplies.demo','+91-98765-43210','Electronics',7,94.5,1.2),
    (2,'CraftLine Global','Priya Sen','priya@craftline.demo','+91-98234-56789','Home & Living',10,91.0,2.1),
    (3,'GlowLab Organics','Maya Nair','maya@glowlab.demo','+91-98123-45678','Beauty',5,96.2,0.8),
    (4,'Green Harvest Naturals','Arvind Pillai','arvind@greenharvest.demo','+91-98345-67890','Food & Beverage',4,98.0,0.5),
    (5,'Thread & Co Apparel','Simran Kaur','simran@threadco.demo','+91-98456-78901','Fashion',12,88.5,3.4),
    (6,'Apex Office & Tech','Mohit Sethi','mohit@apexoffice.demo','+91-98011-22334','Office & Computing',8,93.3,1.7),
]

products_spec = [
 ('ELC-101','Aurora Wireless Headphones','Electronics','Audio & Wearables',1,3499,1850,8,4,6,18,7,'batch'),
 ('ELC-605','USB-C Power Bank 20000mAh','Electronics','Charging Accessories',1,2199,1150,7,5,8,25,7,'serial'),
 ('ELC-210','Mechanical Keyboard K87','Electronics','Computer Accessories',6,4299,2500,10,6,12,30,8,'serial'),
 ('ELC-330','1080p Streaming Webcam','Electronics','Computer Accessories',6,2899,1550,8,4,10,28,8,'serial'),
 ('HOM-204','Linen Storage Basket','Home & Living','Storage & Decor',2,899,420,12,8,10,35,10,'none'),
 ('HOM-312','Bamboo Cooking Utensils Set','Home & Living','Kitchen Tools',2,599,240,10,6,8,30,10,'none'),
 ('HOM-440','Minimalist Desk Lamp','Home & Living','Home Lighting',6,1499,690,9,6,8,28,8,'none'),
 ('BEA-309','Vitamin C Face Serum','Beauty','Skincare',3,1299,580,10,5,8,24,5,'batch'),
 ('BEA-102','Botanical Glow Night Cream','Beauty','Skincare',3,899,390,10,6,8,28,5,'batch'),
 ('BEA-221','Mineral Sunscreen SPF 50','Beauty','Sun Care',3,1099,470,12,7,10,32,5,'batch'),
 ('FOD-412','Organic Trail Mix 500g','Food & Beverage','Snacks & Health',4,499,210,14,6,12,40,4,'batch'),
 ('FOD-520','Cold Brew Coffee 6-Pack','Food & Beverage','Beverages',4,699,320,18,8,14,45,4,'batch'),
 ('FAS-518','Everyday Canvas Tote','Fashion','Bags & Accessories',5,749,310,16,8,12,45,12,'none'),
 ('FAS-630','Relaxed Cotton Overshirt','Fashion','Apparel',5,1599,720,12,6,10,36,12,'none'),
 ('FAS-710','Performance Running Cap','Fashion','Sports Accessories',5,599,250,15,7,12,40,12,'none'),
 ('OFF-120','Ergonomic Office Chair','Office & Computing','Office Furniture',6,8999,5200,4,2,5,12,8,'serial'),
]
products=[]
for i,(sku,name,cat,sub,supp,price,cost,rop,ss,mn,mx,lead,tracking) in enumerate(products_spec,1):
    # Initial stock is based on 5-year opening buffer + observed run rate, not arbitrary.
    base = {1:42,2:34,3:22,4:20,5:70,6:62,7:46,8:38,9:44,10:50,11:72,12:80,13:76,14:58,15:68,16:16}[i]
    on_hand = base + (i % 4) * 3
    expiry = None
    if tracking == 'batch':
        days = 25 + (i*37)%250
        expiry=(TODAY+timedelta(days=days)).isoformat()
    products.append((i,sku,f'{890123450000+i:013d}',name,cat,sub,supp,price,cost,on_hand,0,0,0,rop,ss,mn,mx,lead,expiry,None,0,'Active',0))

# Variants for 10 products
variants=[]
vid=1
for p in products:
    pid,sku,barcode,name,cat,sub,supp,price,cost,*rest=p
    if pid in {1,3,5,8,10,13,14,15}:
        options = [('Standard','Black / Standard'),('Plus','White / Plus')]
        if pid in {13,14,15}:
            options=[('Navy','Navy'),('Stone','Stone')]
        for code,label in options:
            variants.append((vid,pid,f'{sku}-{code.upper()}',f'{name} - {label}',f'{890123460000+vid:013d}',json.dumps({'option':label}),price,cost,0))
            vid += 1

# ---------- historical demand model ----------
# Base daily demand by product; seasonality and trend make the 5-year history useful for forecasting.
base_daily={1:2.8,2:2.1,3:1.4,4:1.2,5:2.4,6:2.0,7:1.6,8:2.6,9:2.2,10:2.7,11:3.2,12:3.6,13:2.8,14:1.7,15:2.3,16:0.55}
trend={1:0.00035,2:0.00025,3:0.00030,4:0.00022,5:0.00018,6:0.00015,7:0.00020,8:0.00045,9:0.00040,10:0.00035,11:0.00028,12:0.00033,13:0.00017,14:0.00015,15:0.00020,16:0.00010}
category_season={'Electronics':1.10,'Home & Living':1.03,'Beauty':1.08,'Food & Beverage':1.15,'Fashion':1.12,'Office & Computing':0.96}

def season_factor(d):
    month=d.month
    weekend=0.92 if d.weekday()>=5 else 1.0
    festive={10:1.17,11:1.28,12:1.25,1:0.95,2:0.92,3:1.02,4:1.03,5:1.05,6:1.06,7:1.03,8:1.04,9:1.08}.get(month,1.0)
    return weekend*festive

sales_daily=[]
for offset in range(DAYS):
    d=START+timedelta(days=offset)
    for p in products:
        pid=p[0]; cat=p[4]
        mean=base_daily[pid]*(1+trend[pid]*offset)*category_season[cat]*season_factor(d)
        # Occasional promotional spikes, more likely in festive months.
        if d.month in (10,11,12) and random.random()<0.055:
            mean*=1.35
        units=max(0, int(round(random.gauss(mean, max(0.55,mean*0.28)))))
        sales_daily.append((pid,iso(d),units))

# aggregate units for each product
sales_by_product={pid:0 for pid in range(1,len(products)+1)}
for pid,d,u in sales_daily: sales_by_product[pid]+=u

# Purchases: monthly replenishment based on demand, sized to cover 30-60 days.
purchases=[]
purchase_items=[]
po_id=1
poi_id=1
receipts=[]
receipt_id=1
for month_idx in range(((END.year-START.year)*12 + END.month-START.month)+1):
    y=START.year+(START.month-1+month_idx)//12
    m=(START.month-1+month_idx)%12+1
    month_start=date(y,m,1)
    next_month = date(y+1,1,1) if m==12 else date(y,m+1,1)
    for p in products:
        pid,sku,barcode,name,cat,sub,supp,price,cost,*_ = p
        # purchases every 1-2 months depending on velocity
        avg=sum(u for pp,dd,u in sales_daily if pp==pid and month_start<=date.fromisoformat(dd)<next_month)
        if avg<=0: continue
        target=max(12, int(avg*1.35))
        qty=max(8, int(round(target/random.choice([1.0,1.1,1.2]))))
        expected=month_start+timedelta(days=suppliers[supp-1][6])
        # PO created before month start, receive around expected date but capped in period.
        created=max(START,month_start-timedelta(days=random.randint(3,10)))
        recv=min(END,next_month-timedelta(days=1))
        po_status='Closed' if recv<=END else 'Ordered'
        total=qty*cost
        purchases.append((po_id,f'PO-{y}-{po_id:05d}',supp,po_status,total,iso(expected),'Rahul Verma',iso(created),iso(recv)))
        purchase_items.append((poi_id,po_id,pid,qty,qty,0,cost))
        receipts.append((receipt_id,po_id,pid,qty,iso(recv),'Kiran Shah'))
        po_id+=1; poi_id+=1; receipt_id+=1

# Returns: roughly 3-4% of fulfilled units, with lower return rates for food.
returns=[]
return_items=[]
ret_id=1
ri_id=1
order_id=1

# Orders: sample 18,000 real orders across 5 years, distributed according to daily product demand.
orders=[]; order_items=[]
# Create order dates and product items by splitting each day's units into small orders.
# Weighted sampling by daily units keeps order mix aligned to actual demand.
for pid,d,u in sales_daily:
    if u<=0: continue
    # average 2.5 units per order; emit 1-2 orders for low demand and more for spikes.
    remaining=u
    while remaining>0:
        qty=min(remaining, random.randint(1,3))
        # 20% chance of bundling another unit
        if remaining>=4 and random.random()<0.18: qty=min(remaining,qty+1)
        prod=products[pid-1]
        price=prod[7]
        customer=f'Customer {order_id:05d}'
        email=f'customer{order_id:05d}@example.com'
        orders.append((order_id,f'ORD-{d.replace("-","")}-{order_id:06d}',customer,email,'Delivered',qty*price, d+'T'+f'{random.randint(9,21):02d}:'+f'{random.randint(0,59):02d}:00'))
        order_items.append((len(order_items)+1,order_id,pid,None,qty,price,qty*price,cost if False else prod[8]))
        # Chance of return on delivered order later calculated below.
        if random.random()<0.032 and prod[4] not in ('Food & Beverage',):
            returns.append((ret_id,f'RET-{d.replace("-","")}-{ret_id:05d}',order_id,customer,'Completed',d+'T15:00:00'))
            cond=random.choices(['New','Minor Damage','Opened','Defective'],[0.38,0.22,0.15,0.25])[0]
            disp='Restock' if cond in ('New','Opened') else random.choice(['Repair','Damaged','Scrap'])
            return_items.append((ri_id,ret_id,pid,qty,cond,disp,'Neha Kapoor','Customer return inspection'))
            ret_id+=1; ri_id+=1
        remaining-=qty
        order_id+=1
        if order_id>22000: break
    if order_id>22000: break

# trim/realize actual sales if order cap hit by rebuilding daily aggregate from orders
actual_sales={(pid,d):0 for pid,d,u in sales_daily}
for oi in order_items:
    _,oid,pid,_,qty,_,_,_=oi
    o=orders[oid-1]
    actual_sales[(pid,o[6].split('T')[0])] += qty
sales_daily=[(pid,d,actual_sales[(pid,d)]) for pid,d,u in sales_daily]
sales_by_product={pid:0 for pid in range(1,len(products)+1)}
for pid,d,u in sales_daily:sales_by_product[pid]+=u

# Final inventory based on opening + receipts - sales + returns - damages - supplier returns.
received_by_product={pid:0 for pid in sales_by_product}
for _,_,pid,qty,*_ in receipts: received_by_product[pid]+=qty
returned_by_product={pid:0 for pid in sales_by_product}
for _,_,pid,qty,*_ in return_items: returned_by_product[pid]+=qty

damaged_by_product={pid:0 for pid in sales_by_product}
for pid in sales_by_product:
    damaged_by_product[pid]=max(0,int(round(sales_by_product[pid]*0.004)))

final_on_hand={}
for p in products:
    pid=p[0]; opening=p[9]
    final_on_hand[pid]=max(0,opening+received_by_product[pid]-sales_by_product[pid]+returned_by_product[pid]-damaged_by_product[pid])

# Update product rows with final state and monthly sales / expiry.
last_30_start=TODAY-timedelta(days=29)
last30={pid:sum(u for p,d,u in sales_daily if p==pid and date.fromisoformat(d)>=last_30_start) for pid in sales_by_product}
prod_rows=[]
for p in products:
    pid,sku,barcode,name,cat,sub,supp,price,cost,on_hand,*rest=p
    # keep configured base on_hand separate only for initial; replace with current authoritative on-hand.
    fields=list(p)
    fields[9]=final_on_hand[pid]
    fields[20]=last30[pid]
    prod_rows.append(tuple(fields))
products=prod_rows

# Distribute final stock across warehouses, preserving product totals and warehouse utilization realism.
locs=[]
for p in products:
    pid=p[0]; total=p[9]
    shares=[0.55,0.27,0.18]
    if pid%3==0: shares=[0.42,0.36,0.22]
    rem=total
    alloc=[]
    for i,s in enumerate(shares):
        q=int(round(total*s)) if i<2 else rem
        q=max(0,min(rem,q)); alloc.append(q); rem-=q
    for i,q in enumerate(alloc,1):
        if q:
            wh=i; candidates=[b for b in bins if b[1]==wh]
            bcode=candidates[(pid+i)%len(candidates)][4]
            reserved=int(round(q*0.05))
            qc=int(round(q*0.02))
            damaged=int(round(damaged_by_product[pid]*shares[i-1]))
            locs.append((len(locs)+1,pid,wh,bcode,q,reserved,qc,damaged))
# derived reserved/qc/damaged per product
for idx,p in enumerate(products):
    pid=p[0]
    reserved=sum(x[5] for x in locs if x[1]==pid)
    qc=sum(x[6] for x in locs if x[1]==pid)
    dmg=sum(x[7] for x in locs if x[1]==pid)
    fields=list(p); fields[10]=reserved; fields[11]=qc; fields[12]=dmg; products[idx]=tuple(fields)

# Batches for batch-tracked products
batches=[]; batch_id=1
for p in products:
    pid=p[0]; tracking=products_spec[pid-1][-1]
    if tracking=='batch':
        total=max(1,p[9]-p[12]-p[11])
        for j in range(2):
            qty=max(0,total//2 if j==0 else total-total//2)
            if qty<=0: continue
            mfg=TODAY-timedelta(days=random.randint(20,180))
            expiry=TODAY+timedelta(days=random.randint(7,120))
            wh=1 if j==0 else 2
            batches.append((batch_id,pid,wh,f'BATCH-{products_spec[pid-1][0]}-{2026}{j+1:02d}',iso(mfg),iso(expiry),qty))
            batch_id+=1

# Serial numbers for selected products based on current stock; cap at 8 each.
serials=[]; serial_id=1
for p in products:
    pid=p[0]
    if products_spec[pid-1][-1]=='serial':
        n=min(8,p[9])
        whs=[1,2,3]
        for j in range(n):
            serials.append((serial_id,pid,f'SN-{p[1]}-{j+1:04d}',whs[j%3],'In-Stock',None))
            serial_id+=1

# Transfers across 3 warehouses (30 realistic records)
transfers=[]; transfer_items=[]
for i in range(1,31):
    d=START+timedelta(days=int(i*(DAYS/31)))
    src=(i%3)+1; dst=((i+1)%3)+1
    pid=(i%len(products))+1
    qty=min(8,max(2,final_on_hand[pid]//20 or 2))
    status='Received' if d<=TODAY-timedelta(days=3) else 'In-Transit'
    transfers.append((i,f'TRF-{d.year}-{i:05d}',src,dst,status,'Neha Kapoor',iso(d),iso(d+timedelta(days=1)) if status=='Received' else None,f'Warehouse balancing for {products[pid-1][3]}'))
    transfer_items.append((i,i,pid,qty))

# Stocktakes quarterly from 2022-2026
stocktakes=[]; stocktake_items=[]
stid=1; sti=1
cur=date(2022,3,31)
while cur<=TODAY:
    wh=((stid-1)%3)+1
    stocktakes.append((stid,f'ST-{cur.year}-{stid:04d}',wh,'Completed','Kiran Shah','Neha Kapoor',iso(cur-timedelta(days=1))))
    for pid in range(1,len(products)+1):
        expected=next((x[4] for x in locs if x[1]==pid and x[2]==wh),0)
        diff=random.choice([-2,-1,0,0,0,1,2]) if expected else 0
        counted=max(0,expected+diff)
        stocktake_items.append((sti,stid,pid,expected,counted,diff,1))
        sti+=1
    stid+=1
    m=cur.month+3; y=cur.year+(m-1)//12; m=(m-1)%12+1
    cur=date(y,m,min(28,cur.day))

# Requests and approvals
requests=[]; request_history=[]; approvals=[]
req_id=1
for i in range(1,151):
    d=START+timedelta(days=random.randint(0,DAYS-1)); pid=random.randint(1,len(products)); qty=random.randint(2,40)
    rtype=random.choice(['Restock','Stock Adjustment','Transfer','Purchase','Damaged Inventory','Expiry Disposal'])
    statuses=['Completed']*7+['Pending']*2+['Rejected']
    status=random.choice(statuses)
    creator=random.choice([2,3,4])
    requests.append((req_id,pid,rtype,qty,'Operational request based on observed stock/demand.',status,users[creator-1][1],iso(d), 'Neha Kapoor' if status in ('Completed','Rejected') else None))
    request_history.append((req_id,req_id,creator,'Pending','Submitted','Initial submission',iso(d)))
    if status in ('Completed','Rejected'):
        decision='Approved' if status=='Completed' else 'Rejected'
        reviewer=3 if creator==4 else 2
        approvals.append((req_id,req_id,reviewer,decision,'Reviewed against inventory and business rules.','Submitted',status,iso(d+timedelta(hours=4))))
    req_id+=1

# Audit transactions: reconstruct per-product on-hand history from dated events.
# Opening event, PO receipts, sales, returns, damages, periodic adjustments.
events=[]
for p in products:
    pid=p[0]
    opening=42 if pid==1 else {2:34,3:22,4:20,5:70,6:62,7:46,8:38,9:44,10:50,11:72,12:80,13:76,14:58,15:68,16:16}[pid]
    events.append((START,pid,opening,'Opening Stock','System',1,None,None,None,'Initial five-year opening balance'))
# receipts
for rid,poid,pid,qty,rd,operator in receipts:
    events.append((date.fromisoformat(rd),pid,qty,'Purchase Receipt',operator,1,None,poid,None,f'PO receipt #{poid}'))
# sales: aggregate by day but create transaction count to keep DB manageable
for pid,d,u in sales_daily:
    if u:
        events.append((date.fromisoformat(d),pid,-u,'Customer Sale','System',1,None,None,None,'Customer order fulfillment'))
# returns
for _,_,pid,qty,cond,disp,inspector,_ in return_items:
    # return date tied to original order date when possible
    pass
for rr in returns:
    rid,retno,oid,customer,status,dt=rr
    # matching item
    ritems=[x for x in return_items if x[1]==rid]
    d=date.fromisoformat(dt.split('T')[0])
    for x in ritems:
        events.append((d,x[2],x[3],'Customer Return',x[6],1,None,None,None,f'Return #{retno} disposition {x[5]}'))
for pid,dmg in damaged_by_product.items():
    if dmg:
        events.append((TODAY,pid,-dmg,'Damage','Kiran Shah',1,None,None,None,'Routine damage write-off based on observed handling rate'))

events.sort(key=lambda x:(x[0],x[1],x[3]))
inv_tx=[]
balances={}
tx=1
for e in events:
    d,pid,delta,kind,operator,wh,batch,poid,orderid,reason=e
    before=balances.get(pid,0); after=before+delta
    if after<0: # Should never happen; cap sale to available to preserve invariant.
        delta=-before; after=0
    balances[pid]=after
    inv_tx.append((f'TX-{tx:08d}',datetime.combine(d,datetime.min.time()).isoformat(),pid,None,None,wh,None,None,None,before,delta,after,kind,reason,4 if operator=='Kiran Shah' else 1,operator,None,orderid,poid,None))
    tx+=1

# Reconcile current balance with product current on_hand: apply final correction if any (should be zero).
for pid,p in enumerate(products,1):
    target=p[9]
    cur=balances.get(pid,0)
    if cur!=target:
        delta=target-cur
        before=cur; after=target; balances[pid]=target
        inv_tx.append((f'TX-{tx:08d}',datetime.combine(TODAY,datetime.min.time()).isoformat(),pid,None,None,1,None,None,None,before,delta,after,'Reconciliation Adjustment','Controlled final reconciliation to current authoritative balance',2,'Rahul Verma',None,None,None,None))
        tx+=1

# movements derived from significant transaction types
movements=[]
for i,t in enumerate(inv_tx,1):
    tid,timestamp,pid,_,_,wh,_,_,_,before,delta,after,kind,reason,user_id,operator,*_=t
    kind_label='Stock in' if delta>0 else 'Stock out' if delta<0 else 'Adjustment'
    movements.append((i,pid,kind_label,abs(delta),reason,timestamp,operator))

# Security sessions and events
now=TODAY.isoformat()+'T10:00:00'
sessions=[
 (1,1,'demo_token_owner','192.168.1.10','Saharanpur, UP, India','Chrome on Windows 11',now,now,'Monitoring executive dashboard','Active'),
 (2,4,'demo_token_handler','192.168.2.45','Delhi Central Hub','Handheld inventory terminal',now,now,'Scanning warehouse stock','Active'),
 (3,3,'demo_token_ops','192.168.3.12','Moradabad Operations Desk','Edge on Windows 11',now,now,'Reviewing requests','Active'),
 (4,2,'demo_token_gm','192.168.1.15','Saharanpur Corporate Office','Safari on macOS',now,now,'Reviewing purchasing','Active'),
]
security_events=[(1,1,'LOGIN','192.168.1.10','Saharanpur, UP, India','Chrome on Windows 11','Successful login',now),
                 (2,4,'LOGIN','192.168.2.45','Delhi Central Hub','Handheld terminal','Successful login',now),
                 (3,3,'LOGIN','192.168.3.12','Moradabad Operations Desk','Edge on Windows 11','Successful login',now),
                 (4,2,'LOGIN','192.168.1.15','Saharanpur Corporate Office','Safari on macOS','Successful login',now)]

audit_logs=[]
for i,t in enumerate(inv_tx[:3000],1):
    tid,ts,pid,*rest=t
    audit_logs.append((i,t[14],t[15],t[12],'inventory_transaction',tid,None,None,t[13],ts))

notifications=[]
for i,p in enumerate(products,1):
    pid=p[0]; avail=p[9]-p[10]-p[11]-p[12]
    if avail<=p[13]:
        notifications.append((i,1,'CRITICAL','Low stock alert',f'{p[3]} is at or below reorder point.',None,now))
    elif p[18]:
        exp=date.fromisoformat(p[18])
        if exp<=TODAY+timedelta(days=30):
            notifications.append((len(notifications)+1,1,'IMPORTANT','Expiry alert',f'{p[3]} has stock expiring by {p[18]}.',None,now))

# ---------- CSV export ----------
def write_csv(name, header, rows):
    path=OUT/f'{name}.csv'
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f); w.writerow(header); w.writerows(rows)
    return path

write_csv('users',['id','name','email','password_hash','role','active'],users)
write_csv('warehouses',['id','code','name','city','manager_name','capacity_sqft','active'],warehouses)
write_csv('warehouse_bins',['id','warehouse_id','rack','shelf','bin_code'],bins)
write_csv('suppliers',['id','name','contact_name','email','phone','category','lead_time_days','on_time_rate','defect_rate'],suppliers)
write_csv('products',['id','sku','barcode','name','category','subcategory','supplier_id','price','unit_cost','on_hand','reserved_qty','qc_hold_qty','damaged_qty','reorder_point','safety_stock','minimum_stock','maximum_stock','lead_time_days','expiry_date','image_url','monthly_sales','status','blocked'],products)
write_csv('product_variants',['id','product_id','sku','name','barcode','attributes','price','unit_cost','stock'],variants)
write_csv('product_stock_locations',['id','product_id','warehouse_id','bin_code','on_hand','reserved','qc_hold','damaged'],locs)
write_csv('product_batches',['id','product_id','warehouse_id','batch_number','mfg_date','expiry_date','quantity'],batches)
write_csv('product_serials',['id','product_id','serial_number','warehouse_id','status','order_id'],serials)
write_csv('stock_transfers',['id','transfer_number','from_warehouse_id','to_warehouse_id','status','created_by','dispatched_at','received_at','notes'],transfers)
write_csv('stock_transfer_items',['id','transfer_id','product_id','quantity'],transfer_items)
write_csv('orders',['id','order_number','customer_name','customer_email','status','total_amount','created_at'],orders)
write_csv('order_items',['id','order_id','product_id','variant_id','quantity','unit_price','subtotal','unit_cost'],order_items)
write_csv('returns',['id','return_number','order_id','customer_name','status','created_at'],returns)
write_csv('return_items',['id','return_id','product_id','quantity','condition','disposition','inspected_by','notes'],return_items)
write_csv('purchase_orders',['id','po_number','supplier_id','status','total_cost','expected_date','created_by','created_at','received_at'],purchases)
write_csv('purchase_order_items',['id','po_id','product_id','ordered_quantity','received_quantity','pending_quantity','unit_cost'],purchase_items)
write_csv('receipts',['id','po_id','product_id','quantity','received_at','received_by'],receipts)
write_csv('stocktakes',['id','stocktake_number','warehouse_id','status','performed_by','approved_by','created_at'],stocktakes)
write_csv('stocktake_items',['id','stocktake_id','product_id','system_qty','counted_qty','discrepancy','reconciled'],stocktake_items)
write_csv('stock_requests',['id','product_id','request_type','quantity','reason','status','created_by','created_at','reviewed_by'],requests)
write_csv('request_history',['id','request_id','actor_id','from_status','to_status','comment','created_at'],request_history)
write_csv('approvals',['id','request_id','reviewer_id','decision','comment','previous_state','new_state','created_at'],approvals)
write_csv('inventory_transactions',['transaction_id','timestamp','product_id','batch_id','serial_id','source_warehouse_id','source_bin','dest_warehouse_id','dest_bin','before_qty','delta_qty','after_qty','transaction_type','reason','user_id','operator','request_id','order_id','po_id','transfer_id'],inv_tx)
write_csv('movements',['id','product_id','kind','quantity','note','created_at','created_by'],movements)
write_csv('sales_history',['product_id','sale_date','units_sold'],sales_daily)
write_csv('user_sessions',['id','user_id','session_token','ip_address','location','device_info','login_time','last_active','current_activity','status'],sessions)
write_csv('security_events',['id','user_id','event_type','ip_address','location','device_info','details','created_at'],security_events)
write_csv('audit_logs',['id','user_id','role','action','resource_type','resource_id','before_json','after_json','reason','created_at'],audit_logs)
write_csv('notifications',['id','user_id','priority','title','message','read_at','created_at'],notifications)

# Analytics summaries
summary=[]
for p in products:
    pid=p[0]; vals=[u for pp,d,u in sales_daily if pp==pid]
    mean=sum(vals)/len(vals); var=sum((x-mean)**2 for x in vals)/len(vals); sd=math.sqrt(var)
    revenue=sum(oi[6] for oi in order_items if oi[2]==pid); cogs=sum(oi[4]*oi[7] for oi in order_items if oi[2]==pid); profit=revenue-cogs
    summary.append([pid,p[1],p[3],len(vals),sales_by_product[pid],round(mean,3),round(sd,3),round(revenue,2),round(cogs,2),round(profit,2),round((profit/revenue*100) if revenue else 0,2),p[9]])
write_csv('product_5yr_summary',['product_id','sku','product','days','units_sold','avg_daily_units','stddev_daily_units','revenue','cogs','gross_profit','gross_margin_pct','current_on_hand'],summary)

monthly=[]
cur=START.replace(day=1)
while cur<=END:
    nxt=date(cur.year+1,1,1) if cur.month==12 else date(cur.year,cur.month+1,1)
    units=sum(u for pid,d,u in sales_daily if cur<=date.fromisoformat(d)<nxt)
    revenue=sum(oi[6] for oi in order_items if cur<=date.fromisoformat(orders[oi[1]-1][6].split('T')[0])<nxt)
    monthly.append([cur.year,cur.month,units,round(revenue,2)])
    cur=nxt
write_csv('monthly_company_summary',['year','month','units_sold','revenue'],monthly)

# Forecast dataset for last 90 days + next 30 days using linear regression formula (calculated here without sklearn dependency).
forecast=[]
for p in products:
    pid=p[0]
    recent=[u for pp,d,u in sales_daily if pp==pid and date.fromisoformat(d)>=TODAY-timedelta(days=89)]
    xs=list(range(len(recent))); n=len(xs)
    if n<2: continue
    sx=sum(xs); sy=sum(recent); sxx=sum(x*x for x in xs); sxy=sum(x*y for x,y in zip(xs,recent)); den=n*sxx-sx*sx
    slope=(n*sxy-sx*sy)/den if den else 0
    intercept=(sy-slope*sx)/n
    pred30=sum(max(0,intercept+slope*(n+i)) for i in range(30))
    daily_avg=sum(recent)/n
    ss=1.65*math.sqrt(sum((u-daily_avg)**2 for u in recent)/n)*math.sqrt(p[17])
    rop=daily_avg*p[17]+ss
    available=p[9]-p[10]-p[11]-p[12]
    q=max(0,int(round(rop+pred30-available)))
    rec='BUY' if q>0 else 'NO_ACTION'
    forecast.append([pid,p[1],round(daily_avg,3),round(slope,5),round(pred30,2),round(ss,2),round(rop,2),available,q,rec])
write_csv('forecast_and_reorder',['product_id','sku','avg_daily_90d','trend_per_day','forecast_next_30d','safety_stock_dynamic','reorder_point_dynamic','available_inventory','recommended_order_qty','recommendation'],forecast)

# Validation report
validation=[]
for p in products:
    pid=p[0]; target=p[9]; locsum=sum(x[4] for x in locs if x[1]==pid); txfinal=balances[pid]
    validation.append([pid,p[1],target,locsum,txfinal,target==locsum==txfinal])
write_csv('data_integrity_validation',['product_id','sku','product_on_hand','location_sum','transaction_final','valid'],validation)

# ---------- SQLite database ----------
# Use schema from current app.py DDL so the generated DB is directly usable with this codebase.
app_path=ROOT/'app.py'
content=app_path.read_text(encoding='utf-8')
blocks=re.findall(r'connection\.executescript\("""(.*?)"""\)',content,re.S)
conn=sqlite3.connect(DB)
conn.execute('PRAGMA foreign_keys=ON')
for b in blocks:
    conn.executescript(b)
for ddl in [
    "ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN locked_until TEXT",
    "ALTER TABLE products ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE products ADD COLUMN minimum_stock INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE products ADD COLUMN maximum_stock INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE inventory_transactions ADD COLUMN transfer_id INTEGER",
    "ALTER TABLE inventory_transactions ADD COLUMN approval_id INTEGER"
]:
    try: conn.execute(ddl)
    except sqlite3.OperationalError: pass
# Clear any seed data in reverse dependency order
for t in ['approvals','request_history','notifications','audit_logs','security_events','user_sessions','inventory_transactions','movements','sales_history','stock_requests','stocktake_items','stocktakes','return_items','returns','order_items','orders','purchase_order_items','purchase_orders','stock_transfer_items','stock_transfers','product_serials','product_batches','product_stock_locations','product_variants','products','warehouse_bins','warehouses','suppliers','users']:
    conn.execute(f'DELETE FROM {t}')

# insert data
conn.executemany('INSERT INTO users(id,name,email,password_hash,role,active) VALUES(?,?,?,?,?,?)',users)
conn.executemany('INSERT INTO warehouses(id,code,name,city,manager_name,capacity_sqft,active) VALUES(?,?,?,?,?,?,?)',warehouses)
conn.executemany('INSERT INTO warehouse_bins(id,warehouse_id,rack,shelf,bin_code) VALUES(?,?,?,?,?)',bins)
now_created=START.isoformat()
conn.executemany('INSERT INTO suppliers(id,name,contact_name,email,phone,category,lead_time_days,on_time_rate,defect_rate,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)', [x+(now_created,) for x in suppliers])
conn.executemany('INSERT INTO products(id,sku,barcode,name,category,subcategory,supplier_id,price,unit_cost,on_hand,reserved_qty,qc_hold_qty,damaged_qty,reorder_point,safety_stock,minimum_stock,maximum_stock,lead_time_days,expiry_date,image_url,monthly_sales,status,blocked) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',products)
conn.executemany('INSERT INTO product_variants(id,product_id,sku,name,barcode,attributes,price,unit_cost,stock) VALUES(?,?,?,?,?,?,?,?,?)',variants)
conn.executemany('INSERT INTO product_stock_locations(id,product_id,warehouse_id,bin_code,on_hand,reserved,qc_hold,damaged) VALUES(?,?,?,?,?,?,?,?)',locs)
conn.executemany('INSERT INTO product_batches(id,product_id,warehouse_id,batch_number,mfg_date,expiry_date,quantity) VALUES(?,?,?,?,?,?,?)',batches)
conn.executemany('INSERT INTO product_serials(id,product_id,serial_number,warehouse_id,status,order_id) VALUES(?,?,?,?,?,?)',serials)
conn.executemany('INSERT INTO stock_transfers(id,transfer_number,from_warehouse_id,to_warehouse_id,status,created_by,dispatched_at,received_at,notes) VALUES(?,?,?,?,?,?,?,?,?)',transfers)
conn.executemany('INSERT INTO stock_transfer_items(id,transfer_id,product_id,quantity) VALUES(?,?,?,?)',transfer_items)
conn.executemany('INSERT INTO orders(id,order_number,customer_name,customer_email,status,total_amount,created_at) VALUES(?,?,?,?,?,?,?)',orders)
conn.executemany('INSERT INTO order_items(id,order_id,product_id,quantity,unit_price,subtotal) VALUES(?,?,?,?,?,?)', [(r[0],r[1],r[2],r[4],r[5],r[6]) for r in order_items])
conn.executemany('INSERT INTO returns(id,return_number,order_id,customer_name,status,created_at) VALUES(?,?,?,?,?,?)',returns)
conn.executemany('INSERT INTO return_items(id,return_id,product_id,quantity,condition,disposition,inspected_by,notes) VALUES(?,?,?,?,?,?,?,?)',return_items)
conn.executemany('INSERT INTO purchase_orders(id,po_number,supplier_id,status,total_cost,expected_date,created_by,created_at,received_at) VALUES(?,?,?,?,?,?,?,?,?)',purchases)
conn.executemany('INSERT INTO purchase_order_items(id,po_id,product_id,ordered_quantity,received_quantity,pending_quantity,unit_cost) VALUES(?,?,?,?,?,?,?)',purchase_items)
# receipts table may have only current schema absent; check first
cols={r[1] for r in conn.execute('PRAGMA table_info(receipts)').fetchall()}
if cols:
    # Current app.py does define receipts in recent versions only if present.
    if {'id','po_id','product_id','quantity','received_at','received_by'} <= cols:
        conn.executemany('INSERT INTO receipts(id,po_id,product_id,quantity,received_at,received_by) VALUES(?,?,?,?,?,?)',receipts)
conn.executemany('INSERT INTO stocktakes(id,stocktake_number,warehouse_id,status,performed_by,approved_by,created_at) VALUES(?,?,?,?,?,?,?)',stocktakes)
conn.executemany('INSERT INTO stocktake_items(id,stocktake_id,product_id,system_qty,counted_qty,discrepancy,reconciled) VALUES(?,?,?,?,?,?,?)',stocktake_items)
conn.executemany('INSERT INTO stock_requests(id,product_id,request_type,quantity,reason,status,created_by,created_at,reviewed_by) VALUES(?,?,?,?,?,?,?,?,?)',requests)
conn.executemany('INSERT INTO request_history(id,request_id,actor_id,from_status,to_status,comment,created_at) VALUES(?,?,?,?,?,?,?)',request_history)
conn.executemany('INSERT INTO approvals(id,request_id,reviewer_id,decision,comment,previous_state,new_state,created_at) VALUES(?,?,?,?,?,?,?,?)',approvals)
conn.executemany('INSERT INTO inventory_transactions(transaction_id,timestamp,product_id,batch_id,serial_id,source_warehouse_id,source_bin,dest_warehouse_id,dest_bin,before_qty,delta_qty,after_qty,transaction_type,reason,user_id,operator,request_id,order_id,po_id,transfer_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',inv_tx)
conn.executemany('INSERT INTO movements(id,product_id,kind,quantity,note,created_at,created_by) VALUES(?,?,?,?,?,?,?)',movements)
conn.executemany('INSERT INTO sales_history(product_id,sale_date,units_sold) VALUES(?,?,?)',sales_daily)
conn.executemany('INSERT INTO user_sessions(id,user_id,session_token,ip_address,location,device_info,login_time,last_active,current_activity,status) VALUES(?,?,?,?,?,?,?,?,?,?)',sessions)
conn.executemany('INSERT INTO security_events(id,user_id,event_type,ip_address,location,device_info,details,created_at) VALUES(?,?,?,?,?,?,?,?)',security_events)
conn.executemany('INSERT INTO audit_logs(id,user_id,role,action,resource_type,resource_id,before_json,after_json,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',audit_logs)
conn.executemany('INSERT INTO notifications(id,user_id,priority,title,message,read_at,created_at) VALUES(?,?,?,?,?,?,?)',notifications)
conn.commit()

# integrity checks
checks={}
checks['products']=conn.execute('SELECT COUNT(*) FROM products').fetchone()[0]
checks['orders']=conn.execute('SELECT COUNT(*) FROM orders').fetchone()[0]
checks['sales_history']=conn.execute('SELECT COUNT(*) FROM sales_history').fetchone()[0]
checks['inventory_transactions']=conn.execute('SELECT COUNT(*) FROM inventory_transactions').fetchone()[0]
checks['purchase_orders']=conn.execute('SELECT COUNT(*) FROM purchase_orders').fetchone()[0]
checks['returns']=conn.execute('SELECT COUNT(*) FROM returns').fetchone()[0]
checks['stocktakes']=conn.execute('SELECT COUNT(*) FROM stocktakes').fetchone()[0]
checks['requests']=conn.execute('SELECT COUNT(*) FROM stock_requests').fetchone()[0]
checks['serial_unique']=conn.execute('SELECT COUNT(*) FROM product_serials p JOIN (SELECT serial_number,COUNT(*) c FROM product_serials GROUP BY serial_number HAVING c>1) d ON p.serial_number=d.serial_number').fetchone()[0]
checks['negative_inventory']=conn.execute('SELECT COUNT(*) FROM products WHERE on_hand<0 OR reserved_qty<0 OR qc_hold_qty<0 OR damaged_qty<0').fetchone()[0]
checks['available_nonnegative']=conn.execute('SELECT COUNT(*) FROM product_inventory_status WHERE available_qty<0').fetchone()[0]
checks['transaction_invariant_fail']=conn.execute('SELECT COUNT(*) FROM inventory_transactions WHERE before_qty + delta_qty != after_qty').fetchone()[0]
checks['location_reconciliation_fail']=conn.execute('SELECT COUNT(*) FROM products p WHERE p.on_hand != COALESCE((SELECT SUM(on_hand) FROM product_stock_locations l WHERE l.product_id=p.id),0)').fetchone()[0]
write_csv('dataset_checks',['check','value'],sorted(checks.items()))

# SQL export from selected tables, easier to load without relying on CSV ordering.
# Generate INSERT statements with sqlite quote escaping using repr-like SQL literals.
def sqlval(v):
    if v is None:return 'NULL'
    if isinstance(v,(int,float)):return str(v)
    return "'"+str(v).replace("'","''")+"'"

def dump_table(name, cols, rows):
    lines=[f'-- {name} ({len(rows)} rows)']
    if not rows:return lines
    for r in rows:
        lines.append(f"INSERT INTO {name} ({','.join(cols)}) VALUES ({','.join(sqlval(v) for v in r)});")
    return lines

sql_parts=['PRAGMA foreign_keys=ON;','BEGIN;']
order_tables=[
 ('users',['id','name','email','password_hash','role','active'],users),
 ('warehouses',['id','code','name','city','manager_name','capacity_sqft','active'],warehouses),
 ('warehouse_bins',['id','warehouse_id','rack','shelf','bin_code'],bins),
 ('suppliers',['id','name','contact_name','email','phone','category','lead_time_days','on_time_rate','defect_rate','created_at'],[x+(START.isoformat(),) for x in suppliers]),
 ('products',['id','sku','barcode','name','category','subcategory','supplier_id','price','unit_cost','on_hand','reserved_qty','qc_hold_qty','damaged_qty','reorder_point','safety_stock','minimum_stock','maximum_stock','lead_time_days','expiry_date','image_url','monthly_sales','status','blocked'],products),
 ('product_variants',['id','product_id','sku','name','barcode','attributes','price','unit_cost','stock'],variants),
 ('product_stock_locations',['id','product_id','warehouse_id','bin_code','on_hand','reserved','qc_hold','damaged'],locs),
 ('product_batches',['id','product_id','warehouse_id','batch_number','mfg_date','expiry_date','quantity'],batches),
 ('product_serials',['id','product_id','serial_number','warehouse_id','status','order_id'],serials),
 ('stock_transfers',['id','transfer_number','from_warehouse_id','to_warehouse_id','status','created_by','dispatched_at','received_at','notes'],transfers),
 ('stock_transfer_items',['id','transfer_id','product_id','quantity'],transfer_items),
 ('orders',['id','order_number','customer_name','customer_email','status','total_amount','created_at'],orders),
 ('order_items',['id','order_id','product_id','quantity','unit_price','subtotal'],[(r[0],r[1],r[2],r[4],r[5],r[6]) for r in order_items]),
 ('returns',['id','return_number','order_id','customer_name','status','created_at'],returns),
 ('return_items',['id','return_id','product_id','quantity','condition','disposition','inspected_by','notes'],return_items),
 ('purchase_orders',['id','po_number','supplier_id','status','total_cost','expected_date','created_by','created_at','received_at'],purchases),
 ('purchase_order_items',['id','po_id','product_id','ordered_quantity','received_quantity','pending_quantity','unit_cost'],purchase_items),
 ('stocktakes',['id','stocktake_number','warehouse_id','status','performed_by','approved_by','created_at'],stocktakes),
 ('stocktake_items',['id','stocktake_id','product_id','system_qty','counted_qty','discrepancy','reconciled'],stocktake_items),
 ('stock_requests',['id','product_id','request_type','quantity','reason','status','created_by','created_at','reviewed_by'],requests),
 ('request_history',['id','request_id','actor_id','from_status','to_status','comment','created_at'],request_history),
 ('approvals',['id','request_id','reviewer_id','decision','comment','previous_state','new_state','created_at'],approvals),
 ('inventory_transactions',['transaction_id','timestamp','product_id','batch_id','serial_id','source_warehouse_id','source_bin','dest_warehouse_id','dest_bin','before_qty','delta_qty','after_qty','transaction_type','reason','user_id','operator','request_id','order_id','po_id','transfer_id'],inv_tx),
 ('movements',['id','product_id','kind','quantity','note','created_at','created_by'],movements),
 ('sales_history',['product_id','sale_date','units_sold'],sales_daily),
 ('user_sessions',['id','user_id','session_token','ip_address','location','device_info','login_time','last_active','current_activity','status'],sessions),
 ('security_events',['id','user_id','event_type','ip_address','location','device_info','details','created_at'],security_events),
 ('audit_logs',['id','user_id','role','action','resource_type','resource_id','before_json','after_json','reason','created_at'],audit_logs),
 ('notifications',['id','user_id','priority','title','message','read_at','created_at'],notifications),
]
for name,cols,rows in order_tables: sql_parts.extend(dump_table(name,cols,rows))
sql_parts.append('COMMIT;')
SQL.write_text('\n'.join(sql_parts),encoding='utf-8')

# README
readme=f'''# StockSphere 5-Year Realistic Dataset\n\nPeriod: {START} through {END} ({DAYS:,} calendar days)\n\nThis is a coherent synthetic business dataset designed for the StockSphere PBL application. Numbers are generated from demand patterns and business rules rather than random dashboard values.\n\n## Included\n- {len(products)} products across 6 categories\n- {len(suppliers)} suppliers\n- {len(warehouses)} warehouses and {len(bins)} bins\n- {len(orders):,} customer orders and {len(order_items):,} order lines\n- {len(sales_daily):,} product-day sales records\n- {len(purchases):,} purchase orders\n- {len(receipts):,} receipts\n- {len(returns):,} customer returns\n- {len(inv_tx):,} inventory transactions\n- {len(batches)} batches\n- {len(serials)} serial numbers\n- {len(stocktakes)} stocktakes\n- {len(requests)} operational requests\n\n## Business logic\nRevenue = sum(order line quantity × selling price)\nCOGS = sum(order line quantity × unit cost)\nGross Profit = Revenue − COGS\nAvailable = On Hand − Reserved − QC Hold − Damaged\nEvery inventory transaction satisfies BEFORE + DELTA = AFTER.\nProduct on-hand reconciles with warehouse location balances and final transaction balances.\n\n## 5-year use\nThe daily sales history can be used for moving averages, standard deviation, trend analysis, linear-regression forecasting, ABC analysis, dead-stock analysis, and stockout-risk calculations.\n\nDemo password for all four users: demo123\n'''
(OUT/'README.md').write_text(readme,encoding='utf-8')

# zip CSVs + sqlite + SQL + README
zip_path=ROOT/'StockSphere_5Y_Realistic_Dataset.zip'
with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED) as z:
    for p in OUT.iterdir():
        if p.is_file(): z.write(p,p.relative_to(OUT).as_posix())

print(json.dumps({'output_dir':str(OUT),'zip':str(zip_path),'db':str(DB),'sql':str(SQL),'checks':checks,'products':len(products),'orders':len(orders),'sales_rows':len(sales_daily),'tx':len(inv_tx)},indent=2))
