---
layout: post
title: "A detailed Introduction to Kerberos Authentication"
date: 2026-01-06 12:00:00 +0000
categories: [kerberos, offensive-security, supply-chain, research]
description: "Learn About How Kerberos Work"
---

# Kerberos: The Ticket Flow (Simple, Practical)

When you log in, Kerberos gives you a reusable identity token so you don't need to keep sending your password.

## The Flow

### 1. Logon → Request TGT

You authenticate to the **KDC (Domain Controller)** with credentials. If correct, the KDC issues a **TGT (Ticket Granting Ticket)**. 

Think of it as a **day pass**.

### 2. Access a Service → Request Service Ticket

For each service (file share, SQL, HTTP), your computer presents the TGT to the KDC and requests a **Service Ticket (TGS)** for that specific service, identified by an **SPN (Service Principal Name)**.

### 3. Present Service Ticket to the Service

You give the service the service ticket. The service validates it and grants access according to its own permissions.

## Key Points

- **TGT** proves identity to the KDC
- **Service Ticket** proves identity to the target service
- Services still enforce authorization — the ticket proves **who you are**, not **what you can do**

## Real-World Example

Alice logs in and gets a TGT. She needs to query `sql-prod.suhel.local`.

1. Her workstation requests a service ticket for `MSSQLSvc/sql-prod.suhel.local`
2. The service ticket is issued and presented to MSSQL
3. MSSQL then checks if Alice is in the `DBAdmin` group

---

*The ticket authenticates identity; the service authorizes access.*
