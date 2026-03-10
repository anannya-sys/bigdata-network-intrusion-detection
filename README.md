# IDS Project — Real-Time Intrusion Detection, Prevention & Avoidance
## Big Data Analytics (BITE411L) | VIT Vellore

---

## Project Architecture

```
[CSV Dataset]
     │
     ▼
[producer.py]  ──── network_logs topic ────▶  [streaming_detection.py]
  (Kafka Producer)                               (Spark Structured Streaming)
                                                  │        │         │
                                         Console  │  threat_alerts   │  Parquet logs
                                                  │  (Kafka topic)   │  (HDFS / local)
                                                  ▼                  ▼
                                          [prevention.py]   [avoidance_retrain.py]
                                          (Block / Throttle) (Periodic retraining)
                                                  │                  │
                                          audit log ──────────────── model.pkl (updated)
                                                                      │
                                                              feedback to Detection
```

---

## File Structure

```
IDS_Project/
├── data/
│   ├── combined_train_80.csv      ← 80% split (from split_code.py)
│   └── combined_test_20.csv       ← 20% split (from split_code.py)
├── models/
│   └── model.pkl                  ← trained by train_model.py
├── logs/
│   ├── detection_results/         ← Parquet files written by Spark
│   ├── prevention_audit.jsonl     ← audit trail of all defensive actions
│   ├── retrain_history.jsonl      ← history of retraining cycles
│   ├── prevention.log
│   └── avoidance.log
├── scripts/
│   └── split_code.py              ← combine + split dataset (run once)
│
├── producer.py                    ← STEP 2: Kafka data producer
├── train_model.py                 ← STEP 1: Train and save model
├── streaming_detection.py         ← STEP 3: Spark detection layer
├── prevention.py                  ← STEP 4: Automated response layer
├── avoidance_retrain.py           ← STEP 5: Periodic model retraining
└── random_forest_model.py         ← standalone batch evaluation script
```

---

## Setup

### 1. Install Python dependencies
```bash
pip install kafka-python pyspark pandas scikit-learn joblib pyarrow
```

### 2. Start Kafka (Docker — easiest)
```bash
docker run -d --name zookeeper -p 2181:2181 confluentinc/cp-zookeeper:latest
docker run -d --name kafka -p 9092:9092 \
  -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092 \
  confluentinc/cp-kafka:latest
```

### 3. Create Kafka topics
```bash
kafka-topics.sh --create --topic network_logs  --bootstrap-server localhost:9092 --partitions 3
kafka-topics.sh --create --topic threat_alerts --bootstrap-server localhost:9092 --partitions 3
```

### 4. Prepare dataset
Place `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` in `data/`, then:
```bash
python scripts/split_code.py
```

---

## Running the Pipeline

Open **4 separate terminals** and run in this order:

### Terminal 1 — Train the model (run once)
```bash
python train_model.py
```

### Terminal 2 — Start Spark detection
```bash
python streaming_detection.py
```

### Terminal 3 — Start the Kafka producer (sends data)
```bash
python producer.py
```

### Terminal 4 — Start prevention layer
```bash
python prevention.py
```

### Terminal 5 (optional, scheduled) — Retrain model
```bash
python avoidance_retrain.py
```

---

## Dashboard (Optional)

You can launch an interactive dashboard to explore detection, prevention, and retraining logs:

```bash
pip install streamlit plotly
streamlit run dashboard.py
```

The dashboard reads from `logs/detection_results/`, `logs/prevention_audit.jsonl`, and `logs/retrain_history.jsonl` and shows:
- Traffic and attacks over time
- Attack distribution by category
- Prevention actions taken (BLOCK / THROTTLE / NONE)
- Model accuracy over retraining cycles

---

## Layer Descriptions

### Detection Layer (`streaming_detection.py`)
- Consumes `network_logs` Kafka topic using Spark Structured Streaming
- Parses JSON payloads into a typed schema
- Applies Random Forest model via a Spark UDF for low-latency inference
- Three output sinks:
  - **Console**: live monitoring
  - **Kafka** (`threat_alerts`): pushes ATTACK events to prevention layer
  - **Parquet** (local/HDFS): archives all results for avoidance/retraining

### Prevention Layer (`prevention.py`)
- Pure Python Kafka consumer — no Spark required, runs independently
- Decides action based on attack category:

| Attack Category | Action   |
|-----------------|----------|
| DoS / DDoS      | BLOCK    |
| Exploits        | BLOCK    |
| Shellcode/Worm  | BLOCK    |
| Reconnaissance  | THROTTLE |
| Fuzzers         | THROTTLE |
| Unknown         | BLOCK    |

- Set `DRY_RUN = False` in `prevention.py` to execute real firewall commands
- Writes full audit trail to `logs/prevention_audit.jsonl`

### Avoidance Layer (`avoidance_retrain.py`)
- Reads Parquet detection logs from HDFS
- Combines with original training data
- Retrains a new Random Forest model
- Replaces `model.pkl` ONLY if the new model achieves higher accuracy
- Logs every cycle outcome to `logs/retrain_history.jsonl`
- **Feedback loop**: detection layer automatically picks up the updated model

---

## Dataset

**UNSW-NB15** — Network Intrusion Detection  
45 features per flow including: protocol, service, state, bytes, rate, TTL, TCP flags, jitter, and more.

Labels:
- `0` = Normal / Benign traffic
- `1` = Attack (Exploits, DoS, Reconnaissance, Fuzzers, Backdoor, etc.)

---

## Acknowledgements


Originally developed as part of an academic project; now maintained as a personal project.
