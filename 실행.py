import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from urllib.parse import urlparse
import csv

# === [1] 장치 설정 ===
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("실행 장치:", device)

# === [2] 모델과 토크나이저 불러오기 ===
model = DistilBertForSequenceClassification.from_pretrained("saved_model").to(device)
tokenizer = DistilBertTokenizerFast.from_pretrained("saved_model")

# === [3] Majestic Million에서 안전 도메인 로딩 ===
safe_domains = set()
with open("majestic_million.csv", newline='', encoding='utf-8') as f:
    reader = csv.reader(f)
    next(reader)  # 헤더 건너뜀
    for row in reader:
        domain = row[2].strip().lower()
        if domain:
            safe_domains.add(domain)

# === [4] URL 정규화 및 도메인 추출 ===
def get_domain(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc.lower()
    except:
        return ""

# === [5] 예측 함수 ===
def predict_url(url: str):
    norm_url = url.strip()
    domain = get_domain(norm_url)

    # [도메인 보정 1단계] 안전 도메인이면 무조건 "안전"
    if domain in safe_domains:
        print(f"\n🌐 URL: {url}")
        print(f"→ 예측 결과: 🟢 안전 (신뢰도: 도메인 기반 우선 판단)")
        return

    # 모델 예측
    model.eval()
    inputs = tokenizer(norm_url, return_tensors="pt", truncation=True, padding="max_length", max_length=128)
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1).squeeze()
        label = torch.argmax(probs).item()
        confidence = probs[label].item()

        # [도메인 보정 2단계] 위험인데 신뢰도 낮으면 주의로 완화
        if label == 0 and confidence < 0.85:
            label = 1

        label_str = {0: "🔴 위험", 1: "🟡 주의", 2: "🟢 안전"}[label]
        print(f"\n🌐 URL: {url}")
        print(f"→ 예측 결과: {label_str} (신뢰도: {confidence:.2f})")

# === [6] 사용자 입력 반복 ===
while True:
    user_input = input("\nURL 입력 (exit 입력 시 종료): ").strip()
    if user_input.lower() == "exit":
        break
    predict_url(user_input)
