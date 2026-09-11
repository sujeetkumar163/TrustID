# TrustID — Multi-Evidence Explainable Document Authenticity Engine
**Smart India Hackathon 2026** | **Problem Statement ID:** SIH26188  
**Team:** Team Conqueror (Team ID: SIH-56)  
**Theme:** Cybersecurity & Digital Fraud Prevention  

---

## 📌 Executive Summary
Conventional document screening tools rely on a single, opaque CNN model (`DOC -> CNN -> FAKE 87%`), providing zero explainability to officers, banks, or courts.

**TrustID** checks an identity document (Aadhaar, PAN) using **5 independent layers of evidence**, synthesizes them using deterministic arithmetic into an **Authenticity Score (0–100)**, and outputs an audit-ready, explainable dossier detailing **why** a document is risky, **which field** is suspicious, and **what action** (ACCEPT, MANUAL REVIEW, ESCALATE) is recommended.

---

## 🏗️ Architecture Matrix (Official Presentation Slide #3)

| Layer | Status | Implementation Details |
| :--- | :--- | :--- |
| **1. OCR & Field Extraction** | **BUILT** | Tesseract / EasyOCR with regex field parsing (Name, ID, DOB, Confidence) |
| **2. Deterministic Rule Validators** | **BUILT** | Aadhaar Verhoeff $D_5$ mathematical checksum algorithm + PAN structure/entity-type validator |
| **3. Visual Forensics** | **PROTOTYPE** | Error Level Analysis (ELA) via PIL/OpenCV measuring JPEG compression delta variance |
| **4. Deep Forgery Model** | **PROTOTYPE STUB** | Clearly labeled `PROTOTYPE_STUB` mirroring forensic signals without overclaiming unverified CNN accuracy |
| **5. Evidence Fusion Engine** | **BUILT** | Weighted multi-evidence fusion with anti-fraud safeguards (insufficient coverage prevention) |
| **6. Report Dashboard UI** | **BUILT** | Explainable Report Card matching the PPT "Explainable Output — Sample Report" format |
| **7. DigiLocker / Hologram** | **ROADMAP** | Live API Setu cross-checking & multi-spectral optical verification |

---

## 🔒 Locked API Contract (Shared Day-0 Schema)
The FastAPI backend returns the exact locked JSON contract on `POST /analyze`:
```json
{
  "extracted_fields": {
    "name": "ANSH GUPTA",
    "id_number": "5432 1098 7654",
    "dob": "15/08/2002",
    "confidence": 0.93
  },
  "rule_checks": {
    "aadhaar_checksum": "PASS",
    "pan_checksum": "PASS"
  },
  "forensics": {
    "ela_risk": "MEDIUM",
    "flagged_regions": ["id_number"]
  },
  "deep_model": {
    "tamper_score": 0.84,
    "status": "PROTOTYPE_STUB"
  },
  "fusion": {
    "score": 62,
    "risk_level": "MEDIUM",
    "action": "MANUAL_REVIEW",
    "reasons": [
      "ID-number region suspicious",
      "DOB mismatch"
    ]
  }
}
```

---

## 🚀 How to Run Locally

### Option A: 1-Click Launch (Recommended for Windows)
1. Double-click `backend/run.bat` to launch the FastAPI Uvicorn server on `http://127.0.0.1:8000`.
2. Double-click `index.html` to open the frontend dashboard in any browser.

### Option B: Manual Command Line
1. Open a terminal in the `backend/` folder:
   ```bash
   cd backend
   pip install -r requirements.txt
   python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
   ```
2. Open `index.html` in your web browser. The status badge will automatically display:
   `Engine: FastAPI Backend (Port 8000)`

---

## 🌐 Deploy to Vercel (Static / Serverless)

The frontend features a **Dual-Engine Architecture**:
- **With Backend Running**: Calls the live Python FastAPI `POST /analyze` endpoint.
- **On Vercel Static Hosting**: Automatically runs the in-browser HTML5 Canvas ELA engine and client-side Verhoeff validation. **You can upload any document directly on Vercel without configuring a backend server!**

### Steps to Deploy:
1. Push this repository to GitHub.
2. Sign in to [vercel.com](https://vercel.com) and click **Add New > Project**.
3. Import your GitHub repository.
4. Leave the build command empty and click **Deploy**.
5. Vercel deploys the site with full drag-and-drop document screening immediately.

---

## 🧪 Sample Documents Included for Demo
In the `sample_documents/` folder, you will find ready-to-test identity documents:
- `sample_aadhaar_genuine.png` — Valid 12-digit Aadhaar passing Verhoeff checksum.
- `sample_aadhaar_edited_dob.png` — Tampered Aadhaar with a spliced DOB patch triggering ELA forensics.
- `sample_pan_card_valid.png` — Valid PAN card conforming to Income Tax Dept entity rules (`P` for Individual).

---

## 🎤 5-Step Demo Script for Presentation
1. **Open with the Problem (15 sec)**: *"Conventional tools output an opaque 'Fake 87%' with zero reasoning. When denying a passport or bank account, that's unacceptable."*
2. **Show the Upload Feature**: Drag and drop `sample_aadhaar_genuine.png` into the upload box and click **Analyze Document**.
3. **Walk Through the 5-Layer Progress**: Point out OCR extraction, Verhoeff mathematical checksum, ELA forensics, and deep stub evaluation.
4. **Show the Explainable Report Card**: Highlight how the output mirrors Slide #2 with the green `PASS` badge, low risk, and `ACCEPT` recommendation.
5. **Demonstrate Tampering Detection**: Upload `sample_aadhaar_edited_dob.png` or click **EDITED_DOB**. Watch the score drop to 66 (`MEDIUM RISK`), and show how the system pinpoints the exact spliced region (`DOB region suspicious`).
