#!/usr/bin/env python3
"""
CERT-In RAG Seeder — populate Qdrant with CERT-In advisory text.

Embeds real CERT-In advisory content (Directions 2022 + advisories CI-2022 to
CI-2024) into Qdrant so the LangGraph RAG agent can answer questions like:
  "What are the CERT-In reporting requirements for ransomware?"
  "Which CERT-In advisory covers APT36 / Transparent Tribe?"
  "What is the mandatory reporting deadline for a data breach?"

Usage:
    python scripts/seed_certin_rag.py
    python scripts/seed_certin_rag.py --qdrant-url http://localhost:6333

Requires: pip install qdrant-client sentence-transformers
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import uuid
from dataclasses import dataclass

# ── Embedded CERT-In advisory content ───────────────────────────────────────
# Representative content from CERT-In Directions 2022 and public advisories.
# In production: scrape https://www.cert-in.org.in/s2cMainServlet

CERTIN_DOCUMENTS: list[dict] = [
    {
        "id": "certin-directions-2022-s1",
        "title": "CERT-In Directions 2022 — Section 1: Mandatory Reporting",
        "source": "CERT-In Directions 2022 under Section 70B of IT Act 2000",
        "category": "regulation",
        "text": (
            "CERT-In Directions 2022 — Mandatory Reporting Requirements. "
            "All organisations (government, private, critical infrastructure operators) must report "
            "cybersecurity incidents to CERT-In within 6 hours of becoming aware. "
            "Failure to report is punishable under Section 70B of the IT Act 2000. "
            "Reporting must be done via the CERT-In incident portal at https://incident.cert-in.org.in "
            "or by email to incident@cert-in.org.in. "
            "The 6-hour deadline applies from the time of first detection or awareness of the incident, "
            "not from the time of confirmation. Organisations must report even if investigation is ongoing."
        ),
        "tags": ["mandatory_reporting", "6_hour_deadline", "it_act_2000", "section_70b"],
    },
    {
        "id": "certin-directions-2022-s2",
        "title": "CERT-In Directions 2022 — Incident Categories CAT-1 to CAT-10",
        "source": "CERT-In Directions 2022 Annexure I",
        "category": "regulation",
        "text": (
            "CERT-In Directions 2022 — Reportable Incident Categories. "
            "CAT-1: Targeted scanning/probing of critical networks. "
            "CAT-2: Compromise of critical systems or information. "
            "CAT-3: Unauthorised access to IT systems/data. "
            "CAT-4: Defacement of websites or unauthorised changes to website content. Also applies to Ransomware — Malicious code attacks. "
            "CAT-5: Attacks on Internet infrastructure (DNS, BGP, routing). "
            "CAT-6: Identity theft, spoofing, phishing attacks. "
            "CAT-7: Denial of Service (DoS) and Distributed DoS (DDoS) attacks. "
            "CAT-8: Attacks on critical infrastructure (power, telecom, financial, healthcare, transport). "
            "CAT-9: Data breach or theft of personal/sensitive personal data. "
            "CAT-10: Attacks on critical information infrastructure (CII) as designated by NCIIPC. "
            "All categories require mandatory reporting within 6 hours."
        ),
        "tags": ["incident_categories", "cat1_cat10", "mandatory_reporting", "nciipc"],
    },
    {
        "id": "certin-directions-2022-s3",
        "title": "CERT-In Directions 2022 — Log Retention and VPN Requirements",
        "source": "CERT-In Directions 2022 Section 3",
        "category": "regulation",
        "text": (
            "CERT-In Directions 2022 — Log Retention Requirements. "
            "All organisations must maintain logs of ICT systems and infrastructure for a rolling period of 180 days. "
            "Logs must be stored within Indian jurisdiction. "
            "VPN service providers must maintain logs of users for a period of 5 years. "
            "Data centres, cloud service providers, and virtual private server providers must maintain "
            "customer information and activity logs. "
            "Cryptocurrency exchanges must maintain KYC and financial transaction records for 5 years. "
            "ICT infrastructure must synchronise with the National Physical Laboratory (NPL) or the "
            "National Informatics Centre (NIC) time servers to maintain accurate timestamps for all logs."
        ),
        "tags": ["log_retention", "180_days", "vpn", "cloud_providers", "time_sync"],
    },
    {
        "id": "certin-advisory-ci-2024-0018",
        "title": "CERT-In Advisory CI-2024-0018 — APT36 Transparent Tribe targeting education sector",
        "source": "CERT-In Advisory CI-2024-0018",
        "category": "advisory",
        "text": (
            "CERT-In Advisory CI-2024-0018 (April 2024) — APT36 / Transparent Tribe Campaign. "
            "Pakistan-linked threat actor APT36 (also known as Transparent Tribe, Mythic Leopard) "
            "has been observed targeting Indian education institutions including CBSE, universities, "
            "and government training academies. "
            "Tactics: Spear-phishing emails with Crimson RAT dropper disguised as educational documents. "
            "Techniques: T1566.001 (spear-phishing attachments), T1059.001 (PowerShell), T1071.001 (C2 over HTTP). "
            "Tools used: Crimson RAT, Transparent Tribe RAT (TTRAT), CrimsonRAT v2. "
            "IOCs: Domains using .education, .academy, .cbse TLD patterns; IPs in Pakistan ASNs AS9260 and AS45595. "
            "Recommended actions: Block APT36 IOCs at email gateway, deploy UEBA for bulk data access, "
            "enable MFA for all exam coordinator accounts, monitor for anomalous database queries."
        ),
        "tags": ["apt36", "transparent_tribe", "education", "cbse", "crimson_rat", "spear_phishing"],
    },
    {
        "id": "certin-advisory-ci-2023-009",
        "title": "CERT-In Advisory CI-2023-009 — Critical Infrastructure OT/ICS Threats",
        "source": "CERT-In Advisory CI-2023-009",
        "category": "advisory",
        "text": (
            "CERT-In Advisory CI-2023-009 (November 2023) — Threats to Operational Technology (OT) and ICS. "
            "Multiple China-linked and Pakistan-linked threat actors have been observed conducting "
            "reconnaissance and pre-positioning activities against Indian critical infrastructure. "
            "Volt Typhoon (Bronze Silhouette, China-linked) has been observed using living-off-the-land "
            "techniques to map OT networks in power generation, water treatment, and telecom sectors. "
            "Key IOCs: native Windows tools (netsh, ipconfig, tracert, net view) used for network discovery "
            "from OT workstations; Modbus and DNP3 protocol anomalies. "
            "CERT-In mandates: Immediate NCIIPC notification for any confirmed OT security incident. "
            "Recommended: Deploy industrial protocol deep packet inspection at IT-OT boundary, "
            "implement strict network segmentation between IT and OT zones, "
            "never isolate OT hosts automatically (risk of physical process disruption)."
        ),
        "tags": ["ot_ics", "volt_typhoon", "power_grid", "modbus", "dnp3", "nciipc", "living_off_land"],
    },
    {
        "id": "certin-advisory-ci-2022-aiims",
        "title": "CERT-In Post-Incident Report — AIIMS Delhi Ransomware 2022",
        "source": "CERT-In Public Incident Report November 2022",
        "category": "incident_report",
        "text": (
            "CERT-In Post-Incident Analysis — AIIMS Delhi Ransomware November 2022. "
            "The All India Institute of Medical Sciences (AIIMS) Delhi suffered a ransomware attack "
            "on 23 November 2022. Attackers encrypted approximately 1.3 TB of data across 40 servers. "
            "The National Informatics Centre (NIC) eHospital system was rendered completely unavailable "
            "for approximately 15 days. Patient care was disrupted — manual paper-based operations deployed. "
            "Root cause: Unpatched systems running End-of-Life Windows Server versions exploited via "
            "CVE-2017-0144 (EternalBlue) — systems had not received security updates since EOL in January 2020. "
            "Attribution: Initial CERT-In findings suggested China-linked actors; NIA investigation ongoing. "
            "Response gaps identified: No CERT-In report filed within 6-hour mandatory window; "
            "log retention inadequate; OT/clinical systems not isolated from admin network. "
            "Key recommendation: Healthcare CNI operators must maintain separate network segments "
            "for clinical vs administrative systems, maintain immutable backups, and patch EoL systems."
        ),
        "tags": ["aiims", "healthcare", "ransomware", "eol_windows", "eternalblue", "cni", "2022_incident"],
    },
    {
        "id": "certin-advisory-ransomware-lockbit",
        "title": "CERT-In Alert — LockBit 3.0 Ransomware targeting India organisations",
        "source": "CERT-In Alert CIAD-2023-0001",
        "category": "advisory",
        "text": (
            "CERT-In Alert CIAD-2023-0001 — LockBit 3.0 / LockBit Black Ransomware Targeting India. "
            "LockBit 3.0 (also known as LockBit Black) ransomware group has been actively targeting "
            "Indian organisations including government agencies, healthcare providers, and financial institutions. "
            "Attack vector: EternalBlue (CVE-2017-0144) exploitation of unpatched Windows systems, "
            "RDP brute force, phishing with malicious macros. "
            "Techniques: T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery (VSS deletion), "
            "T1021.002 SMB lateral movement. "
            "India-specific: High prevalence in government and healthcare sectors due to >70% EoL system rate. "
            "LockBit 3.0 exfiltrates data before encryption (double extortion). "
            "CERT-In classification: CAT-4 Malicious Code Attack — mandatory 6-hour reporting applies. "
            "Recommended: Disable SMBv1, patch CVE-2017-0144, deploy immutable backups, "
            "enable CrowdStrike/Windows Defender Application Guard, implement network segmentation."
        ),
        "tags": ["lockbit", "lockbit3", "ransomware", "eternalblue", "cat4", "double_extortion"],
    },
    {
        "id": "certin-eol-advisory",
        "title": "CERT-In Note — End-of-Life Asset Risk Amplification in India CNI",
        "source": "CERT-In Technical Note TN-2024-003",
        "category": "technical_note",
        "text": (
            "CERT-In Technical Note TN-2024-003 — End-of-Life Asset Risk in Indian Critical Infrastructure. "
            "A 2024 CERT-In survey found that over 70% of government IT assets run End-of-Life (EoL) "
            "operating systems and software (per National Cyber Security Policy 2023). "
            "EoL products receive no security patches — any CVE discovered after EoL date is permanently "
            "unmitigatable without OS/software migration. "
            "Risk amplification: CERT-In recommends treating EoL asset CVE scores as effectively higher "
            "than their NVD CVSS base score, since the vulnerability can never be patched. "
            "Priority EoL systems in India CNI: Windows XP/7/Server 2003/2008/2012, "
            "Siemens S7-300/S7-400 PLCs, GE CIMPLICITY SCADA, Apache HTTP Server 2.2, "
            "Oracle Java 6/7, Red Hat Enterprise Linux 6. "
            "CERT-In mandate: CNI operators must submit EoL system inventory to NCIIPC quarterly "
            "and maintain compensating controls (network isolation, enhanced monitoring) for all EoL assets."
        ),
        "tags": ["eol", "end_of_life", "risk_amplification", "nciipc", "windows7", "cni", "cvss"],
    },
    {
        "id": "certin-nciipc-designation",
        "title": "NCIIPC Critical Information Infrastructure Designation",
        "source": "NCIIPC under IT Act 2000 Section 70",
        "category": "regulation",
        "text": (
            "NCIIPC — Critical Information Infrastructure (CII) Designation under IT Act 2000 Section 70. "
            "NCIIPC (National Critical Information Infrastructure Protection Centre) designates CII sectors: "
            "1. Power and Energy (NTPC, PGCIL, state DISCOMs, nuclear facilities) "
            "2. Banking, Financial Services and Insurance (RBI, SEBI-regulated entities, payment systems) "
            "3. Telecom (BSNL, private carriers, internet exchanges) "
            "4. Transportation (aviation, railways, ports) "
            "5. Government (NIC, UIDAI/Aadhaar, electoral systems) "
            "6. Strategic/Defence (DRDO, defence PSUs, armed forces IT) "
            "7. Healthcare (AIIMS, ESI, government hospitals above 500-bed capacity) "
            "8. Water (major dam control systems, water treatment plants) "
            "Any cybersecurity incident affecting designated CII must be reported to NCIIPC immediately "
            "in addition to the mandatory CERT-In 6-hour report. "
            "Failure to protect CII or report incidents is an offence under Section 70 of the IT Act 2000."
        ),
        "tags": ["nciipc", "cii", "it_act_2000", "section_70", "power", "healthcare", "government"],
    },
    {
        "id": "certin-sidecopy-advisory",
        "title": "CERT-In Advisory — SideCopy APT targeting Indian defence and government",
        "source": "CERT-In Advisory CI-2023-015",
        "category": "advisory",
        "text": (
            "CERT-In Advisory CI-2023-015 — SideCopy (APT-C-24) Campaign Against Indian Defence Sector. "
            "SideCopy, a Pakistan-linked APT group (assessed as subordinate to APT36), has been conducting "
            "sustained operations against Indian defence establishments, ministry officials, and armed forces. "
            "The group is named for its tactic of mimicking the Sidewinder APT group's attack chains. "
            "Primary tools: ReverseRAT, MargulasRAT, njRAT, and custom .NET implants. "
            "Attack vector: Spear-phishing lures using defence-themed documents (procurement, operational orders, admin). "
            "IOC patterns: 60-second C2 beacon intervals, HTTP/S C2 over legitimate-looking domains, "
            "Pakistani hosting providers (AS45595, AS24499). "
            "Techniques: T1566.001, T1059.003, T1071.001, T1082, T1057, T1547.001. "
            "CERT-In classification: CAT-2 Compromise of Critical Systems — mandatory 6-hour reporting. "
            "Recommended: Block known SideCopy IOCs, deploy behavioral detection for 60s HTTP beacon pattern, "
            "enable EDR telemetry on all defence ministry workstations."
        ),
        "tags": ["sidecopy", "apt_c_24", "defence", "government", "reverse_rat", "cat2", "pakistan"],
    },
]


def _chunk_document(doc: dict, chunk_size: int = 512) -> list[dict]:
    """Split large documents into overlapping chunks for better RAG retrieval."""
    text = doc["text"]
    if len(text) <= chunk_size:
        return [doc]

    chunks = []
    words = text.split()
    chunk_words = chunk_size // 6  # approximate word count per chunk
    overlap = chunk_words // 4

    i = 0
    chunk_num = 0
    while i < len(words):
        chunk_text = " ".join(words[i : i + chunk_words])
        chunk_doc = {
            **doc,
            "id": f"{doc['id']}-chunk{chunk_num}",
            "text": chunk_text,
        }
        chunks.append(chunk_doc)
        i += chunk_words - overlap
        chunk_num += 1

    return chunks


def seed_qdrant(qdrant_url: str, collection: str = "certin_advisories") -> None:
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, PointStruct, VectorParams
    except ImportError:
        print("ERROR: qdrant-client not installed. Run: pip install qdrant-client sentence-transformers")
        sys.exit(1)

    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("ERROR: sentence-transformers not installed. Run: pip install sentence-transformers")
        sys.exit(1)

    print(f"Connecting to Qdrant at {qdrant_url}...")
    client = QdrantClient(url=qdrant_url)

    # NOTE: this model + collection name are kept in lock-step with the live
    # retriever in services/agents/app/rag/certin_rag.py (CERTIN_EMBED_MODEL,
    # CERTIN_COLLECTION). Changing one without the other breaks vector search.
    print("Loading embedding model (all-MiniLM-L6-v2)...")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    vector_dim = model.get_sentence_embedding_dimension()

    # Create or recreate collection
    collections = [c.name for c in client.get_collections().collections]
    if collection in collections:
        print(f"Collection '{collection}' exists — deleting for fresh seed...")
        client.delete_collection(collection)

    client.create_collection(
        collection_name=collection,
        vectors_config=VectorParams(size=vector_dim, distance=Distance.COSINE),
    )
    print(f"Created Qdrant collection '{collection}' (dim={vector_dim})")

    # Build chunks
    all_chunks: list[dict] = []
    for doc in CERTIN_DOCUMENTS:
        all_chunks.extend(_chunk_document(doc))

    print(f"Embedding {len(all_chunks)} chunks from {len(CERTIN_DOCUMENTS)} advisories...")
    texts = [c["text"] for c in all_chunks]
    vectors = model.encode(texts, show_progress_bar=True, batch_size=16)

    points = [
        PointStruct(
            id=int(hashlib.md5(chunk["id"].encode()).hexdigest()[:8], 16),
            vector=vectors[i].tolist(),
            payload={
                "doc_id": chunk["id"],
                "title": chunk["title"],
                "source": chunk["source"],
                "category": chunk["category"],
                "text": chunk["text"],
                "tags": chunk.get("tags", []),
            },
        )
        for i, chunk in enumerate(all_chunks)
    ]

    client.upsert(collection_name=collection, points=points)
    print(f"\nSeeded {len(points)} vectors into Qdrant collection '{collection}'")
    print("CERT-In RAG is now functional. The LangGraph certin_agent can query this collection.")

    # Quick sanity check
    test_result = client.search(
        collection_name=collection,
        query_vector=model.encode("What is the CERT-In mandatory reporting deadline?").tolist(),
        limit=2,
    )
    print(f"\nSanity check — top 2 results for 'mandatory reporting deadline':")
    for hit in test_result:
        print(f"  [{hit.score:.3f}] {hit.payload['title']}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Seed CERT-In advisories into Qdrant for RAG")
    parser.add_argument("--qdrant-url", default="http://localhost:6333", help="Qdrant server URL")
    parser.add_argument("--collection", default="certin_advisories", help="Qdrant collection name")
    args = parser.parse_args(argv)

    seed_qdrant(args.qdrant_url, args.collection)


if __name__ == "__main__":
    main()
