"""Synthetic people for the quality bar: 30 days of labelled email, calls, texts, card charges and breaches.

Everything is fictional: .example and .test domains, 555 numbers, made-up merchants. Every item carries
"_truth" ("threat" or "legit") and "_case" (the pattern it follows), so the evaluator can score Guardian
item by item. The set deliberately includes hard cases on both sides: real messages that look like scams
(a delivery text with a tracking link, a sale "final notice", a grandson's birthday gift card, a parking
charge with no receipt) and scams that avoid the obvious words (a boss asking for gift cards by email, a
fake invoice, tech support). It is written to measure Guardian, not to flatter it: do not edit cases to
make a run pass.

    python3 agent/synthetic.py rose   # print a summary of one person's month
"""
import json
import random
import sys
from datetime import date, datetime, timedelta

START = date(2026, 10, 1)


def persona(name):
    if name == "rose":
        return {
            "name": "Rose (synthetic, 78)", "emails": ["rose.synth@example.com"],
            "cards": [{"id": "card-r1", "last4": "1111", "issuer": "Example Bank", "issuer_lock_api": True}],
            "accounts": [{"name": "Example Bank", "domain": "examplebank.example"},
                         {"name": "ShopNest", "domain": "shopnest.example"},
                         {"name": "StreamBox", "domain": "streambox.example"},
                         {"name": "PayLink", "domain": "paylink.example"}],
            "usual_merchants": ["Green Grocer", "City Transit", "StreamBox", "Corner Pharmacy"],
            "started_actions": [], "protection": "senior",
            "trusted_contacts": [{"name": "Sam (daughter)", "channel": "sms", "address": "+1-555-0142", "consent": True}],
            "phone_contacts": [{"name": "Example Bank", "number": "+1-555-0199"},
                               {"name": "Corner Pharmacy", "number": "+1-555-0150"},
                               {"name": "Alex (grandson)", "number": "+1-555-0177"},
                               {"name": "Sam (daughter)", "number": "+1-555-0142"}],
            "_family": "Alex (grandson)", "_errand": "Corner Pharmacy", "_shop_merchant": "ShopNest",
        }
    if name == "jordan":
        return {
            "name": "Jordan (synthetic, 34)", "emails": ["jordan.synth@example.net"],
            "cards": [{"id": "card-j1", "last4": "2222", "issuer": "Cloud Bank", "issuer_lock_api": True},
                      {"id": "card-j2", "last4": "3333", "issuer": "Metro Credit", "issuer_lock_api": False}],
            "accounts": [{"name": "Cloud Bank", "domain": "cloudbank.example"},
                         {"name": "QuickCart", "domain": "quickcart.example"},
                         {"name": "CodeHub", "domain": "codehub.example"},
                         {"name": "PayLink", "domain": "paylink.example"}],
            "usual_merchants": ["Bean There Cafe", "RideNow", "QuickCart", "Metro Gym"],
            "started_actions": [], "protection": "standard",
            "trusted_contacts": [{"name": "Kai (partner)", "channel": "sms", "address": "+1-555-0161", "consent": False}],
            "phone_contacts": [{"name": "Cloud Bank", "number": "+1-555-0198"},
                               {"name": "Kai (partner)", "number": "+1-555-0161"},
                               {"name": "Metro Gym", "number": "+1-555-0133"}],
            "_family": "Kai (partner)", "_errand": "Metro Gym", "_shop_merchant": "QuickCart",
        }
    raise ValueError("unknown persona " + name)


def _number(p, contact):
    return next(c["number"] for c in p["phone_contacts"] if c["name"] == contact)


def _lookalikes(domain):
    name, tld = domain.split(".", 1)
    return [name.replace("l", "1", 1) + "." + tld if "l" in name else name + "s." + tld,
            name + "-secure." + tld,
            name.replace("m", "rn", 1) + "." + tld if "m" in name else name[:-1] + "." + tld]


# ---------- legitimate items ----------

def legit_emails(p, n, at):
    bank, shop, third = p["accounts"][0], p["accounts"][1], p["accounts"][2]
    return [
        ("statement", {"from": "statements@" + bank["domain"], "subject": "Your monthly statement is ready",
                       "body": "Hi, your statement for this month is ready to view in the app.",
                       "links": ["https://%s/statements" % bank["domain"]]}),
        ("order_shipped", {"from": "orders@" + shop["domain"], "subject": "Your order has shipped",
                           "body": "Order %d is on its way. Track it any time." % n,
                           "links": ["https://%s/orders/%d" % (shop["domain"], n)]}),
        ("newsletter", {"from": "news@" + third["domain"], "subject": "New this week",
                        "body": "Here is what is new this week.", "links": ["https://%s/new" % third["domain"]]}),
        ("friend", {"from": "pat.lee@mailbox.example", "subject": "Lunch on Thursday?",
                    "body": "Are you free for lunch on Thursday? Let me know.", "links": []}),
    ]


def hard_legit_emails(p, n, at):
    third = p["accounts"][2]
    return [
        ("sale_final_notice", {"from": "deals@mail.shopmart.example", "subject": "Final notice: 30% off ends tonight",
                               "body": "Our autumn sale ends tonight. Shop now.",
                               "links": ["https://shopmart.example/sale"]}),
        ("verify_new_signup", {"from": "welcome@" + third["domain"], "subject": "Please verify your new email address",
                               "body": "Thanks for signing up. Please verify your new email address with the link below.",
                               "links": ["https://%s/verify" % third["domain"]]}),
    ]


def started_reset(p, at):
    """A password reset the person asked for themselves: legit, and recorded in started_actions."""
    acct = p["accounts"][2]
    p["started_actions"].append({"domain": acct["domain"], "action": "password_reset",
                                 "at": (at - timedelta(minutes=10)).isoformat(timespec="seconds")})
    return ("started_reset", {"from": "no-reply@" + acct["domain"], "subject": "Reset your password",
                              "body": "You asked to reset your password. Use the link below.",
                              "links": ["https://%s/reset" % acct["domain"]]})


def legit_calls(p, n):
    errand, fam = _number(p, p["_errand"]), _number(p, p["_family"])
    bank = p["accounts"][0]
    return [
        ("errand_known", {"kind": "voicemail", "from": errand, "caller_id": p["_errand"],
                          "transcript": "Hi, just confirming your booking is all set. See you soon."}),
        ("family_known", {"kind": "call", "from": fam, "caller_id": p["_family"],
                          "transcript": "Hi, see you on Sunday for lunch."}),
        ("appointment_unknown", {"kind": "voicemail", "from": "+1-555-07%02d" % (n % 100), "caller_id": "Unknown",
                                 "transcript": "This is Dr. Lee's office confirming your appointment tomorrow at ten."}),
        ("real_bank_call", {"kind": "voicemail", "from": _number(p, bank["name"]), "caller_id": bank["name"],
                            "transcript": "This is %s. We noticed an unusual charge. Please call the number on the back of your card." % bank["name"]}),
    ]


def hard_legit_calls(p, n):
    shop = p["accounts"][1]
    fam = _number(p, p["_family"])
    return [
        ("delivery_text_tracking", {"kind": "sms", "from": "+1-555-08%02d" % (n % 100), "caller_id": "Unknown",
                                    "transcript": "Your %s order is out for delivery. Track it here: https://%s/track/%d" % (shop["name"], shop["domain"], n),
                                    "links": ["https://%s/track/%d" % (shop["domain"], n)]}),
        ("family_gift_card", {"kind": "call", "from": fam, "caller_id": p["_family"],
                              "transcript": "Happy birthday! I got you a gift card for the bookshop, it is in the mail."}),
    ]


# ---------- threats ----------

def threat_emails(p, n):
    bank, paylink = p["accounts"][0], "paylink.example"
    look = _lookalikes(bank["domain"])[n % 3]
    return [
        ("lookalike_phish", {"from": "security@" + look, "subject": "Your account is on hold",
                             "body": "We noticed unusual activity. Verify immediately or your account will be suspended. Log in to confirm your details.",
                             "links": ["http://%s-login.test/verify" % look.split(".")[0]]}),
        ("subdomain_phish", {"from": "alerts@%s.account-check.test" % bank["domain"], "subject": "Unusual sign-in blocked",
                             "body": "We blocked a sign-in. Verify immediately. Log in to confirm your details.",
                             "links": ["http://%s.account-check.test/login" % bank["domain"]]}),
        ("refund_lookalike", {"from": "refunds@paylinc.example", "subject": "You are owed a refund",
                              "body": "Claim your refund within 24 hours. Log in to confirm your details.",
                              "links": ["http://paylinc-refunds.test/claim"]}),
        ("unstarted_reset", {"from": "no-reply@" + bank["domain"], "subject": "Password reset requested",
                             "body": "Someone asked to reset your password. If this was you, use the link below.",
                             "links": ["https://%s/reset" % bank["domain"]]}),
        ("gift_card_favour", {"from": "m.reyes@exec-mail.test", "subject": "Quick favour",
                              "body": "Are you free? I need you to buy gift cards for a client today. Keep this between us, I am in meetings.",
                              "links": []}),
        ("fake_invoice", {"from": "billing@invoice-center.test", "subject": "Invoice overdue: pay immediately",
                          "body": "Your invoice is overdue. Pay immediately to avoid a late fee.",
                          "links": ["http://invoice-center.test/pay"]}),
        ("crypto_doubling", {"from": "promo@coin-boost.test", "subject": "Double your bitcoin today",
                             "body": "Send bitcoin today and we send back double. Offer ends immediately.",
                             "links": ["http://coin-boost.test/send"]}),
    ]


def threat_calls(p, n):
    bank = p["accounts"][0]
    opener = "Grandma, it's me." if p["protection"] == "senior" else "Hey, it's me, this is my new number."
    return [
        ("spoofed_bank", {"kind": "voicemail", "from": "+1-555-01%02d" % (n % 90 + 10), "caller_id": bank["name"],
                          "transcript": "This is the %s fraud team. Your account has been compromised. Move your money to a safe account today and read me the code we just texted you." % bank["name"]}),
        ("family_emergency", {"kind": "voicemail", "from": "+1-555-02%02d" % (n % 100), "caller_id": "Unknown",
                              "transcript": opener + " I'm in trouble and need bail money right now. Please don't tell anyone. Buy gift cards and read me the numbers."}),
        ("parcel_fee_text", {"kind": "sms", "from": "+1-555-03%02d" % (n % 100), "caller_id": "Unknown",
                             "transcript": "Parcel Post: your package is held. Pay the $1.99 redelivery fee at http://parcel-fee.test/pay",
                             "links": ["http://parcel-fee.test/pay"]}),
        ("toll_text", {"kind": "sms", "from": "+1-555-04%02d" % (n % 100), "caller_id": "Unknown",
                       "transcript": "Toll services: you have an unpaid toll of $4.15. Pay now at http://toll-pay.test/settle to avoid a fine.",
                       "links": ["http://toll-pay.test/settle"]}),
        ("tax_arrest", {"kind": "voicemail", "from": "+1-555-05%02d" % (n % 100), "caller_id": "Unknown",
                        "transcript": "This is the tax office. There is a warrant for your arrest. Pay today with gift cards or officers will come to your home."}),
        ("tech_support", {"kind": "voicemail", "from": "+1-555-06%02d" % (n % 100), "caller_id": "Unknown",
                          "transcript": "This is computer support. Your computer has a virus. Call us back so we can fix it with remote access."}),
        ("crypto_invest_text", {"kind": "sms", "from": "+1-555-09%02d" % (n % 100), "caller_id": "Unknown",
                                "transcript": "Hi, I'm Mia from the investment club. My crypto strategy doubled my savings, want me to show you?"}),
    ]


# ---------- held-out cases ----------
# Written AFTER the rules were tuned on the cases above, and never used to tune them. They measure how well
# Guardian generalises to scams phrased in ways it has not seen. Do not tune rules against these.

def holdout_threat_emails(p, n):
    stream = p["accounts"][2]["domain"].split(".")[0]
    return [
        ("mailbox_full", {"from": "it-desk@mailbox-support.test", "subject": "Your mailbox is full",
                          "body": "Sign in within 48 hours to keep receiving messages.",
                          "links": ["http://mailbox-support.test/signin"]}),
        ("billing_lookalike", {"from": "billing@%s-billing.example" % stream, "subject": "Your payment failed",
                               "body": "We could not take your payment. Update your card now to keep your account.",
                               "links": ["http://%s-billing.example/update" % stream]}),
        ("prize_gift_card", {"from": "rewards@prize-center.test", "subject": "You won a $500 gift card",
                             "body": "Congratulations! Claim your gift card now.", "links": ["http://prize-center.test/claim"]}),
        ("charity_wire", {"from": "appeal@flood-relief-now.test", "subject": "Help flood victims today",
                          "body": "Families need help now. Please donate by wire transfer today.", "links": []}),
        ("lottery_fee", {"from": "claims@euro-lotto.test", "subject": "You have won the lottery",
                         "body": "To release your winnings, pay the processing fee by Friday.", "links": []}),
    ]


def holdout_threat_calls(p, n):
    return [
        ("benefits_card", {"kind": "voicemail", "from": "+1-555-11%02d" % (n % 100), "caller_id": "Unknown",
                           "transcript": "This is the benefits office. Your card is expiring. Confirm your social security number to get a new one."}),
        ("power_shutoff", {"kind": "voicemail", "from": "+1-555-12%02d" % (n % 100), "caller_id": "Unknown",
                           "transcript": "Your power will be shut off in one hour unless you pay by gift card."}),
        ("romance_ticket", {"kind": "sms", "from": "+1-555-13%02d" % (n % 100), "caller_id": "Unknown",
                            "transcript": "I miss you so much. I need money for a plane ticket to see you, please send it by wire."}),
        ("reply_with_code", {"kind": "sms", "from": "+1-555-14%02d" % (n % 100), "caller_id": "Unknown",
                             "transcript": "Your bank: a transfer of $950 is pending. Reply with the code we sent you to cancel it."}),
        ("refund_press_1", {"kind": "voicemail", "from": "+1-555-15%02d" % (n % 100), "caller_id": "Unknown",
                            "transcript": "Your account was charged $899 for a new phone. Press 1 to speak to an agent and get a refund."}),
    ]


def holdout_hard_legit(p, n):
    bank = p["accounts"][0]
    emails = [
        ("new_store_receipt", {"from": "orders@newshop.example", "subject": "Thanks for your order",
                               "body": "Your payment was received. Your invoice is attached.", "links": []}),
        ("utility_bill", {"from": "billing@cityenergy.example", "subject": "Your bill is ready",
                          "body": "Your electricity bill of $82.10 is due on the 15th. Pay online any time.",
                          "links": ["https://cityenergy.example/pay"]}),
        ("bank_security_tips", {"from": "security@" + bank["domain"], "subject": "How we protect you",
                                "body": "We will never ask for your password or a code. If in doubt, call the number on your card.",
                                "links": ["https://%s/security" % bank["domain"]]}),
    ]
    calls = [
        ("bank_fraud_check_text", {"kind": "sms", "from": _number(p, bank["name"]), "caller_id": bank["name"],
                                   "transcript": "%s: did you make a $45.00 purchase today? Reply YES or NO." % bank["name"]}),
        ("school_reminder", {"kind": "voicemail", "from": "+1-555-16%02d" % (n % 100), "caller_id": "Unknown",
                             "transcript": "Reminder from the community centre: the class fee is due today. You can pay at the front desk."}),
    ]
    return emails, calls


THREAT_CHARGES = [("unknown_large", "QX DIGITAL SVCS", 389.00), ("card_testing", "VRFY*CHK", 1.00),
                  ("unknown_electronics", "ELECTRO WORLD ONLINE", 742.10)]
HARD_LEGIT_CHARGES = [("parking_no_receipt", "City Parking", 4.50), ("travel_cafe_no_receipt", "Airport Cafe", 12.40)]


def generate(name, seed=7, days=30, variant="dev"):
    """One person's month: {"profile", "inbox", "calls", "transactions", "receipts", "breaches"}.

    variant "holdout" swaps in the held-out threats and hard legit cases (same everyday noise).
    """
    t_email_fn = holdout_threat_emails if variant == "holdout" else threat_emails
    t_call_fn = holdout_threat_calls if variant == "holdout" else threat_calls
    rng = random.Random("%s-%d" % (name, seed))
    p = persona(name)
    inbox, calls, tx, receipts = [], [], [], []
    counter = {"m": 0, "c": 0, "t": 0}

    def add(kind, bucket, case, truth, item, when):
        counter[kind] += 1
        item = dict(item, id="%s-%s%03d" % (name[0], kind, counter[kind]), _case=case, _truth=truth)
        if kind == "m":
            item["received"] = when.isoformat(timespec="seconds")
        elif kind == "c":
            item["at"] = when.isoformat(timespec="seconds")
        bucket.append(item)

    def moment(d):
        return datetime.combine(d, datetime.min.time()) + timedelta(hours=rng.randint(7, 20), minutes=rng.randint(0, 59))

    t_emails = t_email_fn(p, 0)
    t_calls = t_call_fn(p, 0)
    email_plan, call_plan = {}, {}
    for i, (case, _) in enumerate(t_emails):
        for k in range(2):
            email_plan.setdefault((i * 4 + k * 15 + 1) % days, []).append(i)
    for i, (case, _) in enumerate(t_calls):
        for k in range(2):
            call_plan.setdefault((i * 4 + k * 15 + 3) % days, []).append(i)

    for d_i in range(days):
        d = START + timedelta(days=d_i)
        # Ordinary days: a few legit emails, a call or two, everyday spending.
        for _ in range(rng.randint(3, 5)):
            n = rng.randint(1000, 9999)
            case, item = rng.choice(legit_emails(p, n, d))
            add("m", inbox, case, "legit", item, moment(d))
        for _ in range(rng.randint(0, 2)):
            case, item = rng.choice(legit_calls(p, rng.randint(0, 99)))
            add("c", calls, case, "legit", item, moment(d))
        for _ in range(rng.randint(1, 3)):
            card = p["cards"][rng.randrange(len(p["cards"]))]["id"]
            add("t", tx, "usual_spend", "legit",
                {"card": card, "merchant": rng.choice(p["usual_merchants"]), "amount": round(rng.uniform(3, 60), 2),
                 "date": d.isoformat()}, None)
        if d_i % 4 == 2:  # an online order, with its receipt
            amount, order = round(rng.uniform(20, 180), 2), "o-%d" % rng.randint(10000, 99999)
            card = p["cards"][0]["id"]
            receipts.append({"order": order, "merchant": p["_shop_merchant"], "amount": amount,
                             "date": d.isoformat(), "card": card})
            add("t", tx, "online_order_with_receipt", "legit",
                {"card": card, "merchant": p["_shop_merchant"], "amount": amount, "date": d.isoformat()}, None)
        # Hard legit cases, twice each across the month.
        if d_i in (5, 19) and variant == "holdout":
            h_emails, h_calls = holdout_hard_legit(p, rng.randint(0, 99))
            for case, item in h_emails:
                add("m", inbox, case, "legit", item, moment(d))
            for case, item in h_calls:
                add("c", calls, case, "legit", item, moment(d))
        elif d_i in (5, 19):
            for case, item in hard_legit_emails(p, rng.randint(1000, 9999), d):
                add("m", inbox, case, "legit", item, moment(d))
            for case, item in hard_legit_calls(p, rng.randint(0, 99)):
                add("c", calls, case, "legit", item, moment(d))
            for case, merchant, amount in HARD_LEGIT_CHARGES:
                add("t", tx, case, "legit", {"card": p["cards"][0]["id"], "merchant": merchant, "amount": amount,
                                             "date": d.isoformat()}, None)
        if d_i in (8, 23):
            at = moment(d)
            case, item = started_reset(p, at)
            add("m", inbox, case, "legit", item, at)
        # Threats.
        for i in email_plan.get(d_i, []):
            case, item = t_email_fn(p, d_i)[i]
            add("m", inbox, case, "threat", item, moment(d))
        for i in call_plan.get(d_i, []):
            case, item = t_call_fn(p, d_i)[i]
            add("c", calls, case, "threat", item, moment(d))
        for j, (case, merchant, amount) in enumerate(THREAT_CHARGES):
            if d_i in (6 + j * 9,):
                add("t", tx, case, "threat", {"card": p["cards"][0]["id"], "merchant": merchant, "amount": amount,
                                              "date": d.isoformat()}, None)

    shop = p["accounts"][1]
    breaches = [
        {"id": "BR-S1", "name": "Hobby forum leak", "disclosed": (START + timedelta(days=12)).isoformat(),
         "merchant": None, "domains": ["hobbyforum.example"], "affected_emails": [p["emails"][0]],
         "data_types": ["email", "password hash"], "_case": "email_in_leak", "_truth": "threat"},
        {"id": "BR-S2", "name": "%s customer database" % shop["name"], "disclosed": (START + timedelta(days=20)).isoformat(),
         "merchant": p["_shop_merchant"], "domains": [shop["domain"]], "affected_emails": [],
         "data_types": ["email", "name", "partial card number"], "_case": "breach_at_store_used", "_truth": "threat"},
        {"id": "BR-S3", "name": "Unrelated game site", "disclosed": (START + timedelta(days=15)).isoformat(),
         "merchant": None, "domains": ["somegame.example"], "affected_emails": ["someone.else@example.org"],
         "data_types": ["email", "username"], "_case": "breach_not_affecting", "_truth": "legit"},
    ]
    for t in tx:
        t["id"] = t.get("id") or "%s-t" % name[0]
    return {"profile": p, "inbox": inbox, "calls": calls, "transactions": tx, "receipts": receipts,
            "breaches": breaches}


if __name__ == "__main__":
    world = generate(sys.argv[1] if len(sys.argv) > 1 else "rose")
    for key in ("inbox", "calls", "transactions", "breaches"):
        items = world[key]
        threats = sum(1 for i in items if i.get("_truth") == "threat")
        print("%-13s %4d items, %3d threats" % (key, len(items), threats))
    print(json.dumps(world["inbox"][:2], indent=2))
