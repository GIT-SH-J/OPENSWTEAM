import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from urllib.parse import urlparse

# 라벨 맵 설정
label_map = {"위험": 0, "주의": 1, "안전": 2}
id2label = {v: k for k, v in label_map.items()}

# 모델과 토크나이저 초기화
model = DistilBertForSequenceClassification.from_pretrained(
    "distilbert-base-uncased",
    num_labels=3,
    id2label=id2label,
    label2id=label_map
)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("📟 실행 장치:", device)

# 저장된 모델과 토크나이저 로드
try:
    model = DistilBertForSequenceClassification.from_pretrained("saved_model").to(device)
    tokenizer = DistilBertTokenizerFast.from_pretrained("saved_model")
    model.eval()
except Exception as e:
    print("모델 또는 토크나이저 불러오기 실패:", e)
    exit()

def preprocess_url(url: str) -> str:
    """URL 전처리: 도메인, 경로, 쿼리 분리"""
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    return f"{domain} {path} {query}".strip()

def predict_url(url: str):
    if not url.strip():
        print("입력값이 비어 있습니다.")
        return None, None, None
    try:
        # URL 전처리
        processed_url = preprocess_url(url)
        inputs = tokenizer(processed_url, return_tensors="pt", truncation=True, padding="max_length", max_length=128)
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1).squeeze()
            label = torch.argmax(probs).item()
            confidence = probs[label].item()
            label_str = {0: "🔴 위험", 1: "🟡 주의", 2: "🟢 안전"}.get(label, "알 수 없음")
            print(f"\n🌐 {url}")
            print(f"→ {label_str} (신뢰도: {confidence:.2f})")
            return label, confidence, label_str
    except Exception as e:
        print("예측 중 오류 발생:", e)
        return None, None, None

# 입력 루프
while True:
    user_input = input("\nURL 입력 (종료하려면 'exit'): ").strip()
    if user_input.lower() == "exit":
        break
    predict_url(user_input)