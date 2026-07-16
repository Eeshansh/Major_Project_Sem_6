🛡️ Phishing URL Detection System

A Hybrid Phishing URL Detection System developed as the **Major Project** for the Bachelor of Computer Applications (BCA) program at **Amrita Vishwa Vidyapeetham**.

The application combines a **Rule-Based Detection Engine** with a **Machine Learning (Random Forest)** model to analyze URLs and generate explainable phishing risk assessments. Instead of relying solely on machine learning predictions, the system evaluates lexical, structural, and domain-related characteristics to provide an interpretable security report.

📖 Project Overview

Phishing attacks continue to be one of the most common cybersecurity threats, often deceiving users through carefully crafted malicious URLs. This project aims to assist users in identifying potentially dangerous URLs by combining deterministic security rules with supervised machine learning.

The system performs:

- Rule-Based URL Analysis
- Machine Learning Assessment
- URL Structural Analysis
- Domain Information Analysis
- Explainable Security Observations
- Hybrid Risk Scoring
- Final Security Recommendation

✨ Features

- Hybrid phishing detection architecture
- Rule-Based Detection Engine
- Random Forest Machine Learning classifier
- TF-IDF based lexical hostname analysis
- URL structural feature extraction
- Domain age verification
- URL entropy calculation
- Punycode detection
- URL obfuscation detection
- Suspicious keyword detection
- HTTPS verification
- Explainable phishing risk scoring
- Interactive Flask-based web interface

🏗️ System Architecture
'''
                User
                  │
                  ▼
          Flask Web Application
                  │
        ┌─────────┴─────────┐
        │                   │
        ▼                   ▼
 Rule-Based Engine     ML Prediction
        │                   │
        └─────────┬─────────┘
                  ▼
        Hybrid Decision Engine
                  │
                  ▼
        Security Analysis Report
```



🛠️ Technologies Used
 Programming Languages

- Python
- HTML5
- CSS3 (Tailwind CSS)
- JavaScript

🛠️Frameworks & Libraries

- Flask
- Scikit-learn
- Pandas
- NumPy
- TLDExtract
- python-whois
- Joblib

🛠️Machine Learning

- Random Forest Classifier
- TF-IDF Vectorization

📊 Dataset

This project uses the **PhiUSIIL Phishing URL Dataset** provided by the University of California Irvine (UCI) Machine Learning Repository.

Dataset:
https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

📂 Project Structure

```
Phishing-URL-Detection-System/
│
├── app.py
├── train_model.py
├── requirements.txt
│
├── templates/
│   └── index.html
│
├── static/
│
├── utils/
│   ├── featureExtractor.py
│   ├── rule_engine.py
│   └── ml_model.py
│
├── model/
│   ├── model.pkl
│   └── tfidf.pkl
│
└── README.md
```
Installation

Clone the repository

```bash
git clone https://github.com/yourusername/Phishing-URL-Detection-System.git
```

Navigate to the project

```bash
cd Phishing-URL-Detection-System
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python app.py
```

Open your browser

```
http://127.0.0.1:5000
```

---

📷 Application Screenshots

Home Page

<img width="1428" height="812" alt="image" src="https://github.com/user-attachments/assets/112bed5f-eb53-4f83-855b-24c09f45001c" />


Legitimate URL Detection

<img width="1424" height="652" alt="image" src="https://github.com/user-attachments/assets/fb481a2e-e020-481d-b5ee-721c50a3403b" />
URL:https://platform.openai.com/


Suspicious URL Detection

<img width="1423" height="806" alt="image" src="https://github.com/user-attachments/assets/cd0970b9-d6d3-4963-a20d-46ebf7f21e23" />
URL:http://127.0.0.1:5000/
<img width="1423" height="798" alt="image" src="https://github.com/user-attachments/assets/68546c7a-ccbb-4f84-b59d-795c96eb5622" />
URL:https://shorturl.at/yznPa 



### Phishing URL Detection

<img width="1408" height="799" alt="image" src="https://github.com/user-attachments/assets/f17762e1-466b-4185-8dfd-158dbbdeec2e" />
URL: http://192.168.1.1/login


📈 Key Functionalities

- Lexical URL Analysis
- Structural URL Analysis
- Domain Information Analysis
- Machine Learning Assessment
- Hybrid Risk Score Generation
- Explainable Security Observations
- Final Recommendation Generation

⚠️ Limitations

- Performs static URL analysis only.
- Does not inspect webpage content.
- Does not integrate live threat intelligence feeds.
- WHOIS information may not always be available.
- Machine Learning performance depends on the quality of the training dataset.

🔮 Future Enhancements

- Integration with real-time threat intelligence APIs
- SSL certificate validation
- DNS reputation analysis
- Webpage content inspection
- Browser extension implementation
- Deep Learning based phishing detection
- Continuous model retraining with updated phishing datasets

👨‍🎓 Academic Information

**Project Title**

Phishing URL Detection System

**Degree**

Bachelor of Computer Applications (BCA)

**Institution**

Amrita Vishwa Vidyapeetham

**Academic Year**

2025–2026

📄 License

This repository is intended for academic and educational purposes.

```
© 2026 Eeshansh Bhatnagar
```
